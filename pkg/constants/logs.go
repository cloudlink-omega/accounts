package constants

import "time"

type UserLog struct {
	Timestamp time.Time
	Action    string
	Success   bool
	Message   string
}
