package models

import "time"

type Identity struct {
	Name       string
	CreateTime time.Time
	UpdateTime time.Time
	DeleteTime *time.Time

	AuthMethod AuthMethod
	Password   string
}
