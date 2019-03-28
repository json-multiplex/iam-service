package models

import "time"

type User struct {
	Name       string
	CreateTime time.Time
	UpdateTime time.Time
	DeleteTime *time.Time

	IsRoot      bool
	DisplayName string
}
