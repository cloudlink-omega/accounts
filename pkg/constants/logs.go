package constants

import "time"

type UserLog struct {
	Timestamp time.Time
	Action    string
	Success   bool
	Warn      bool
	Fail      bool
	Message   string
}
