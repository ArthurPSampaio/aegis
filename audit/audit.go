package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

type Entry struct {
	ID        int64
	Event     string
	Actor     string
	Timestamp time.Time
	Hash      string
	PrevHash  string
}

// calcula o hash SHA-256 de uma entrada
// Inclue o hash da entrada anterior para formar o chain
func computeHash(entry Entry) string {
	data := fmt.Sprintf("%d|%s|%s|%s|%s",
		entry.ID,
		entry.Event,
		entry.Actor,
		entry.Timestamp.UTC().Format(time.RFC3339Nano),
		entry.PrevHash,
	)

	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

type Log struct {
	entries []Entry
	nextID  int64
}

func New() *Log {
	return &Log{
		entries: []Entry{},
		nextID:  1,
	}
}

func (l *Log) Add(event string, actor string) Entry {
	prevHash := ""
	if len(l.entries) > 0 {
		prevHash = l.entries[len(l.entries)-1].Hash
	}

	entry := Entry{
		ID:        l.nextID,
		Event:     event,
		Actor:     actor,
		Timestamp: time.Now().UTC(),
		PrevHash:  prevHash,
	}

	entry.Hash = computeHash(entry)

	l.entries = append(l.entries, entry)
	l.nextID++

	return entry
}

// verifica a integridade de todo o log.
func (l *Log) Verify() error {
	for i, entry := range l.entries {
		expectedHash := computeHash(entry)
		if entry.Hash != expectedHash {
			return fmt.Errorf("entrada %d corrompida: hash inválido", entry.ID)
		}

		if i > 0 {
			prevEntry := l.entries[i-1]
			if entry.PrevHash != prevEntry.Hash {
				return fmt.Errorf("entrada %d corrompida: hash anterior não bate", entry.ID)
			}
		}
	}

	return nil
}