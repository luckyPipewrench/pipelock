//go:build enterprise && windows

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import "os"

type exemptionStoreFileLock struct {
	file *os.File
}

func acquireExemptionStoreFileLock(path string) (*exemptionStoreFileLock, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	return &exemptionStoreFileLock{file: file}, nil
}

func (l *exemptionStoreFileLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	return l.file.Close()
}
