package lineage

import (
	"sync"
	"time"

	santapb "buf.build/gen/go/northpolesec/protos/protocolbuffers/go/telemetry"
)

// Key uniquely identifies a process within a boot session.
type Key struct {
	BootUUID   string
	Pid        int32
	PidVersion int32
}

// IsZero reports whether the key has no meaningful value.
func (k Key) IsZero() bool {
	return k.BootUUID == "" && k.Pid == 0 && k.PidVersion == 0
}

// FromProcessID builds a Key from a Santa ProcessID and boot UUID.
func FromProcessID(bootUUID string, pid *santapb.ProcessID) Key {
	if pid == nil {
		return Key{}
	}
	return Key{
		BootUUID:   bootUUID,
		Pid:        pid.GetPid(),
		PidVersion: pid.GetPidversion(),
	}
}

// Node captures execution-time information about a process.
type Node struct {
	Key         Key
	Parent      Key
	Responsible Key

	Path      string
	User      string
	UID       int32
	Group     string
	GID       int32
	SessionID int32

	Args      []string
	StartTime time.Time
	CreatedAt time.Time
}

// Store keeps a bounded, per-boot cache of process nodes for lineage building.
type Store struct {
	mu         sync.RWMutex
	nodes      map[Key]*Node
	maxEntries int
	ttl        time.Duration
}

// Config controls Store behavior.
type Config struct {
	MaxEntries int
	TTL        time.Duration
}

// NewStore creates a new lineage store with sane defaults.
func NewStore(cfg Config) *Store {
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = 50000
	}
	if cfg.TTL <= 0 {
		cfg.TTL = time.Hour
	}
	return &Store{
		nodes:      make(map[Key]*Node, cfg.MaxEntries),
		maxEntries: cfg.MaxEntries,
		ttl:        cfg.TTL,
	}
}

// UpsertFromExecution records or updates a node based on an Execution event.
// It should be called once per execution event.
func (s *Store) UpsertFromExecution(msg *santapb.SantaMessage, ev *santapb.Execution) {
	if msg == nil || ev == nil {
		return
	}

	target := ev.GetTarget()
	if target == nil || target.GetId() == nil {
		return
	}

	boot := msg.GetBootSessionUuid()
	key := FromProcessID(boot, target.GetId())

	now := time.Now()

	var (
		path      string
		userName  string
		uid       int32
		groupName string
		gid       int32
		startTime time.Time
	)

	if exe := target.GetExecutable(); exe != nil {
		path = exe.GetPath()
	}
	if u := target.GetEffectiveUser(); u != nil {
		userName = u.GetName()
		uid = u.GetUid()
	}
	if g := target.GetEffectiveGroup(); g != nil {
		groupName = g.GetName()
		gid = g.GetGid()
	}
	if ts := target.GetStartTime(); ts != nil {
		startTime = ts.AsTime()
	}

	node := &Node{
		Key:         key,
		Parent:      FromProcessID(boot, parentID(ev)),
		Responsible: FromProcessID(boot, target.GetResponsibleId()),
		Path:        path,
		User:        userName,
		UID:         uid,
		Group:       groupName,
		GID:         gid,
		SessionID:   target.GetSessionId(),
		Args:        decodeArgs(ev.GetArgs()),
		StartTime:   startTime,
		CreatedAt:   now,
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Basic TTL-based cleanup on write to prevent unbounded growth.
	s.evictExpiredLocked(now)
	if len(s.nodes) >= s.maxEntries {
		s.evictOldestLocked()
	}

	if s.nodes == nil {
		s.nodes = make(map[Key]*Node, s.maxEntries)
	}
	s.nodes[key] = node
}

// Lineage builds an ancestor chain starting from key, following Parent links.
// The returned slice is ordered from root (oldest ancestor) to leaf (key).
func (s *Store) Lineage(key Key, maxDepth int) []*Node {
	if maxDepth <= 0 {
		maxDepth = 8
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.nodes) == 0 {
		return nil
	}

	chain := make([]*Node, 0, maxDepth)
	current := s.nodes[key]

	seen := make(map[Key]struct{}, maxDepth)

	for current != nil && len(chain) < maxDepth {
		chain = append(chain, current)
		seen[current.Key] = struct{}{}

		if current.Parent.IsZero() {
			break
		}
		next, ok := s.nodes[current.Parent]
		if !ok {
			break
		}
		if _, exists := seen[next.Key]; exists {
			// Cycle detected; abort.
			break
		}
		current = next
	}

	return chain
}

// Serialize converts a lineage chain into a JSON-friendly structure.
func Serialize(nodes []*Node) []map[string]any {
	if len(nodes) == 0 {
		return nil
	}

	out := make([]map[string]any, len(nodes))
	for i, n := range nodes {
		relation := "target"
		if i == 1 {
			relation = "parent"
		} else if i > 1 {
			relation = "ancestor"
		}

		m := map[string]any{
			"relation":   relation,
			"depth":      i,
			"pid":        n.Key.Pid,
			"pidversion": n.Key.PidVersion,
			"path":       n.Path,
			"user":       n.User,
			"uid":        n.UID,
			"group":      n.Group,
			"gid":        n.GID,
			"session_id": n.SessionID,
			"start_time": n.StartTime,
		}
		if len(n.Args) > 0 {
			m["args"] = n.Args
		}
		out[i] = m
	}
	return out
}

func (s *Store) evictExpiredLocked(now time.Time) {
	if s.ttl <= 0 || len(s.nodes) == 0 {
		return
	}
	cutoff := now.Add(-s.ttl)
	for k, n := range s.nodes {
		if n.CreatedAt.Before(cutoff) {
			delete(s.nodes, k)
		}
	}
}

func (s *Store) evictOldestLocked() {
	if len(s.nodes) == 0 {
		return
	}
	var oldestKey Key
	var oldestTime time.Time
	first := true
	for k, n := range s.nodes {
		if first || n.CreatedAt.Before(oldestTime) {
			oldestKey = k
			oldestTime = n.CreatedAt
			first = false
		}
	}
	if !oldestKey.IsZero() {
		delete(s.nodes, oldestKey)
	}
}

func decodeArgs(raw [][]byte) []string {
	if len(raw) == 0 {
		return nil
	}
	out := make([]string, len(raw))
	for i, b := range raw {
		out[i] = string(b)
	}
	return out
}

func parentID(ev *santapb.Execution) *santapb.ProcessID {
	if ev == nil {
		return nil
	}
	if tgt := ev.GetTarget(); tgt != nil && tgt.GetParentId() != nil {
		return tgt.GetParentId()
	}
	if inst := ev.GetInstigator(); inst != nil && inst.GetId() != nil {
		return inst.GetId()
	}
	return nil
}
