package utils

import (
	"fmt"
	"time"
)

// AboutTime converts a time object into a "time ago" format.
func AboutTime(t time.Time) string {
	duration := time.Since(t)

	switch {
	case duration < time.Minute:
		return fmt.Sprintf("%d sec ago", int(duration.Seconds()))
	case duration < time.Hour:
		return fmt.Sprintf("%d min ago", int(duration.Minutes()))
	case duration < 24*time.Hour:
		return fmt.Sprintf("%d hours ago", int(duration.Hours()))
	case duration < 30*24*time.Hour:
		return fmt.Sprintf("%d days ago", int(duration.Hours()/24))
	case duration < 12*30*24*time.Hour:
		return fmt.Sprintf("%d months ago", int(duration.Hours()/24/30))
	default:
		return fmt.Sprintf("%d years ago", int(duration.Hours()/24/365))
	}
}
