// SPDX-License-Identifier: AGPL-3.0-only

package tailer

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"gamertan.com/observatory/internal/agentstate"
	"gamertan.com/observatory/internal/collector"
	"gamertan.com/observatory/internal/config"
	"gamertan.com/observatory/internal/model"
)

const maxDirectoryEntries = 4096
const maxReadBytesPerCycle = 4 << 20

type Result struct {
	Signal       model.Signal
	Observations []model.Observation
	Cursor       agentstate.Cursor
}

type fileIdentity struct{ device, inode uint64 }

func Read(source config.AgentSource, cursor agentstate.Cursor, maximum int, now time.Time) (Result, error) {
	if maximum < 1 || maximum > model.MaxRecords {
		return Result{}, errors.New("tail batch limit is invalid")
	}
	configured, configuredIdentity, err := openRegular(source.Path)
	if errors.Is(err, os.ErrNotExist) {
		return Result{Cursor: cursor}, nil
	}
	if err != nil {
		return Result{}, err
	}
	defer configured.Close()

	active, activeIdentity, rotated := configured, configuredIdentity, false
	if cursor.Device != 0 && (cursor.Device != configuredIdentity.device || cursor.Inode != configuredIdentity.inode) {
		previous, previousIdentity, findErr := findIdentity(filepath.Dir(source.Path), fileIdentity{cursor.Device, cursor.Inode})
		if findErr != nil {
			return Result{}, findErr
		}
		if previous != nil {
			defer previous.Close()
			active, activeIdentity, rotated = previous, previousIdentity, true
		} else {
			cursor.Discontinuities++
			cursor.Device, cursor.Inode, cursor.Offset, cursor.DiscardingLine = configuredIdentity.device, configuredIdentity.inode, 0, false
		}
	}
	if cursor.Device == 0 {
		cursor.Device, cursor.Inode = activeIdentity.device, activeIdentity.inode
	}

	result, atEOF, partial, err := readOpen(active, source, cursor, maximum, now)
	if err != nil {
		return Result{}, err
	}
	if !rotated || len(result.Observations) == maximum || !atEOF {
		return result, nil
	}
	if result.Cursor.DiscardingLine {
		result.Cursor.DroppedRecords++
		result.Cursor.DiscardingLine = false
	} else if partial > 0 {
		result.Cursor.Offset += int64(partial)
		result.Cursor.DroppedRecords++
	}
	result.Cursor.Device, result.Cursor.Inode, result.Cursor.Offset, result.Cursor.DiscardingLine = configuredIdentity.device, configuredIdentity.inode, 0, false
	remaining := maximum - len(result.Observations)
	next, _, _, err := readOpen(configured, source, result.Cursor, remaining, now)
	if err != nil {
		return Result{}, err
	}
	if result.Signal == "" {
		result.Signal = next.Signal
	}
	result.Observations = append(result.Observations, next.Observations...)
	result.Cursor = next.Cursor
	return result, nil
}

func readOpen(file *os.File, source config.AgentSource, cursor agentstate.Cursor, maximum int, now time.Time) (Result, bool, int, error) {
	info, err := file.Stat()
	if err != nil {
		return Result{}, false, 0, err
	}
	identity, err := identity(info)
	if err != nil {
		return Result{}, false, 0, err
	}
	if cursor.Device != identity.device || cursor.Inode != identity.inode {
		cursor.Device, cursor.Inode, cursor.Offset, cursor.DiscardingLine = identity.device, identity.inode, 0, false
	}
	if info.Size() < cursor.Offset {
		cursor.Offset = 0
		cursor.DiscardingLine = false
		cursor.Discontinuities++
	}
	if _, err = file.Seek(cursor.Offset, io.SeekStart); err != nil {
		return Result{}, false, 0, err
	}
	reader := bufio.NewReaderSize(file, 64<<10)
	result := Result{Cursor: cursor}
	discarding := cursor.DiscardingLine
	partial := 0
	readBytes := 0
	pendingBytes := 0
	lineBuffer := make([]byte, 0, 64<<10)
	for len(result.Observations) < maximum {
		fragment, readErr := reader.ReadSlice('\n')
		readBytes += len(fragment)
		switch {
		case readErr == nil:
			if discarding {
				result.Cursor.Offset += int64(len(fragment))
				result.Cursor.DroppedRecords++
				discarding = false
				result.Cursor.DiscardingLine = false
			} else {
				pendingBytes += len(fragment)
				if pendingBytes > collector.MaxLineBytes+1 {
					result.Cursor.Offset += int64(pendingBytes)
					result.Cursor.DroppedRecords++
				} else {
					lineBuffer = append(lineBuffer, fragment...)
					result.Cursor.Offset += int64(pendingBytes)
					line := lineBuffer[:len(lineBuffer)-1]
					if len(line) > 0 && line[len(line)-1] == '\r' {
						line = line[:len(line)-1]
					}
					signal, observation, parseErr := collector.Parse(source.Kind, line, now, source.SensitiveFields...)
					if parseErr != nil {
						result.Cursor.DroppedRecords++
					} else {
						if result.Signal != "" && signal != result.Signal {
							return Result{}, false, 0, errors.New("collector changed signal inside one stream")
						}
						result.Signal = signal
						result.Observations = append(result.Observations, observation)
					}
				}
				pendingBytes = 0
				lineBuffer = lineBuffer[:0]
			}
		case errors.Is(readErr, bufio.ErrBufferFull):
			if discarding {
				result.Cursor.Offset += int64(len(fragment))
			} else {
				pendingBytes += len(fragment)
				if pendingBytes > collector.MaxLineBytes {
					result.Cursor.Offset += int64(pendingBytes)
					pendingBytes = 0
					lineBuffer = lineBuffer[:0]
					discarding = true
					result.Cursor.DiscardingLine = true
				} else {
					lineBuffer = append(lineBuffer, fragment...)
				}
			}
		case errors.Is(readErr, io.EOF):
			if discarding {
				result.Cursor.Offset += int64(len(fragment))
				result.Cursor.DiscardingLine = true
				partial = 0
			} else if pendingBytes+len(fragment) > collector.MaxLineBytes {
				result.Cursor.Offset += int64(pendingBytes + len(fragment))
				result.Cursor.DiscardingLine = true
				partial = 0
			} else {
				partial = pendingBytes + len(fragment)
			}
			return result, true, partial, nil
		default:
			return Result{}, false, 0, readErr
		}
		if readBytes >= maxReadBytesPerCycle {
			return result, false, 0, nil
		}
	}
	return result, false, 0, nil
}

func openRegular(path string) (*os.File, fileIdentity, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fileIdentity{}, err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, fileIdentity{}, err
	}
	if !info.Mode().IsRegular() {
		file.Close()
		return nil, fileIdentity{}, errors.New("collector source must be a regular file")
	}
	value, err := identity(info)
	if err != nil {
		file.Close()
		return nil, fileIdentity{}, err
	}
	return file, value, nil
}

func findIdentity(directory string, wanted fileIdentity) (*os.File, fileIdentity, error) {
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fileIdentity{}, nil
	}
	if err != nil {
		return nil, fileIdentity{}, err
	}
	if len(entries) > maxDirectoryEntries {
		return nil, fileIdentity{}, errors.New("collector directory exceeds safe entry limit")
	}
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 || entry.IsDir() {
			continue
		}
		file, found, openErr := openRegular(filepath.Join(directory, entry.Name()))
		if openErr != nil {
			continue
		}
		if found == wanted {
			return file, found, nil
		}
		file.Close()
	}
	return nil, fileIdentity{}, nil
}

func identity(info os.FileInfo) (fileIdentity, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Dev == 0 || stat.Ino == 0 {
		return fileIdentity{}, fmt.Errorf("collector file identity is unavailable")
	}
	return fileIdentity{device: uint64(stat.Dev), inode: uint64(stat.Ino)}, nil
}
