package models

import "time"

type Account struct {
	Name       string
	CreateTime time.Time
	UpdateTime time.Time
	DeleteTime *time.Time

	DisplayName string
	Root        string
}
