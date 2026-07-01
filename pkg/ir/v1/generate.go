package ir

//go:generate protoc -I=../../.. --go_out=../../.. --go_opt=module=godzilla proto/common.proto proto/instruction.proto proto/function.proto proto/module.proto
