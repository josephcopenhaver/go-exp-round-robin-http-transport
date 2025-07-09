package internal

import (
	"errors"
	"net"
	"syscall"
)

const (
	msgErrRawConnReadFailed    = "syscall.RawConn.Read failed"
	prefixErrRawConnReadFailed = msgErrRawConnReadFailed + ": "
)

var (
	ErrNotSyscallConn  = errors.New("net.Conn instance does not implement syscall.Conn")
	ErrSyscallConnCall = errors.New("SyscallConn call error")

	ErrRawConnReadFailed = errors.New(msgErrRawConnReadFailed)
)

type rawConnReadError struct {
	err error
}

func (e *rawConnReadError) Error() string {
	return prefixErrRawConnReadFailed + e.err.Error()
}

func (e *rawConnReadError) Unwrap() []error {
	return []error{ErrRawConnReadFailed, e.err}
}

var isConnectedSyscallBuf = []byte{0}

// IsConnected reports whether a TCP connection is still logically open.
// It uses a non-blocking peek to check socket state without consuming data.
//
// This only works reliably on Linux and macOS, where syscall.Conn exposes
// the underlying file descriptor, and syscall.Recvfrom supports MSG_PEEK.
//
// It is possible for the error returned to be nil, but the connection to
// be closed as indicated by a false returned boolean value. It is not possible
// for the boolean to be true and the error to be non-nil.
//
// If you do not want to utilize the error returned, you can call
// IsConnectedNoErr instead.
//
// See https://stackoverflow.com/a/58664631/3200607
func IsConnected(conn net.Conn) (bool, error) {

	// supports getting passed a *tls.Conn or similar
	for {
		v, ok := conn.(interface{ NetConn() net.Conn })
		if !ok {
			break
		}
		conn = v.NetConn()
	}

	sconn, ok := conn.(syscall.Conn)
	if !ok {
		return false, ErrNotSyscallConn
	}

	rc, err := sconn.SyscallConn()
	if err != nil {
		return false, errors.Join(ErrSyscallConnCall, err)
	}

	connected := false
	err = rc.Read(func(fd uintptr) bool {
		n, _, err := syscall.Recvfrom(int(fd), isConnectedSyscallBuf, syscall.MSG_PEEK|syscall.MSG_DONTWAIT)

		if err == nil {
			if n != 0 {
				// definitely connected, there is data to read
				connected = true
			}
			// ^ else: definitely not connected, equiv to io.EOF
		} else if err == syscall.EWOULDBLOCK || err == syscall.EAGAIN {
			// no-op, definitely connected still, just no data ready to read yet
			connected = true
		}

		return true
	})
	if err != nil {
		return false, &rawConnReadError{err}
	}

	return connected, nil
}

// IsConnectedNoErr behaves like IsConnected, but does not return an error.
// It is useful when you are only interested in only the boolean value and not the error.
//
// Note that for the purposes of this function, if any error is encountered while
// checking the connection then false will be returned even if the connection is
// logically still established.
//
// It expects the input to implement syscall.Conn and for that implementation to not
// return an error when calling SyscallConn for the check to be fully reliable.
func IsConnectedNoErr(conn net.Conn) bool {

	// supports getting passed a *tls.Conn or similar
	for {
		v, ok := conn.(interface{ NetConn() net.Conn })
		if !ok {
			break
		}
		conn = v.NetConn()
	}

	sconn, ok := conn.(syscall.Conn)
	if !ok {
		return false
	}

	rc, err := sconn.SyscallConn()
	if err != nil {
		return false
	}

	connected := false
	if rc.Read(func(fd uintptr) bool {
		n, _, err := syscall.Recvfrom(int(fd), isConnectedSyscallBuf, syscall.MSG_PEEK|syscall.MSG_DONTWAIT)

		if err == nil {
			if n != 0 {
				// definitely connected, there is data to read
				connected = true
			}
			// ^ else: definitely not connected, equiv to io.EOF
		} else if err == syscall.EWOULDBLOCK || err == syscall.EAGAIN {
			// no-op, definitely connected still, just no data ready to read yet
			connected = true
		}

		return true
	}) != nil {
		return false
	}

	return connected
}
