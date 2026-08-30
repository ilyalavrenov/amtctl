// Copyright (c) Intel Corporation
// SPDX-License-Identifier: Apache-2.0
//
// The record layout, per-sensor description texts and the entity, severity,
// firmware and watchdog tables below are derived from go-wsman-messages
// (github.com/device-management-toolkit/go-wsman-messages).

package amt

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"time"
)

// rawEvent is the fixed 21-byte record AMT stores per event. The firmware
// writes it little-endian with no header.
type rawEvent struct {
	TimeStamp       uint32
	DeviceAddress   uint8
	EventSensorType uint8
	EventType       uint8
	EventOffset     uint8
	EventSourceType uint8
	EventSeverity   uint8
	SensorNumber    uint8
	Entity          uint8
	EntityInstance  uint8
	EventData       [8]uint8
}

// recordBytes is binary.Size(rawEvent{}); an array length needs a constant.
const recordBytes = 21

// decodeEvent turns one base64 record into the printable form. A short record
// reads as zero-padded, which is how firmware leaves a field it does not set.
func decodeEvent(encoded string) (Event, error) {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return Event{}, fmt.Errorf("decode event record: %w", err)
	}

	var padded [recordBytes]byte

	copy(padded[:], decoded)

	var record rawEvent

	if _, err := binary.Decode(padded[:], binary.LittleEndian, &record); err != nil {
		return Event{}, fmt.Errorf("decode event record: %w", err)
	}

	return Event{
		Time:        time.Unix(int64(record.TimeStamp), 0),
		Severity:    severityName(record.EventSeverity),
		Entity:      entityName(record.Entity),
		Description: description(record.EventSensorType, record.EventOffset, record.EventData),
	}, nil
}

// The EventSensorType values AMT's firmware log reports.
const (
	sensorAuthentication = 6
	sensorFirmware       = 15
	sensorWatchdog       = 18
	sensorBootMedia      = 30
	sensorOSLockup       = 32
	sensorBootFailure    = 35
	sensorFirmwareStart  = 37
)

// Tags in the first byte of event data: firmware marks a payload invalid rather
// than omitting it, and a watchdog record carries an agent ID only under its own.
const (
	invalidFirmwareData = 235
	watchdogAgent       = 170
)

// description renders one record's event text. A sensor type with no text of
// its own still leaves the caller severity and entity to go on.
func description(sensorType, eventOffset uint8, data [8]uint8) string {
	switch sensorType {
	case sensorAuthentication:
		attempts := binary.LittleEndian.Uint16(data[1:3])

		return fmt.Sprintf("Authentication failed %d times. The system may be under attack.", attempts)
	case sensorFirmware:
		return firmwareName(eventOffset, data)
	case sensorWatchdog:
		return watchdogName(data)
	case sensorBootMedia:
		return "No bootable media"
	case sensorOSLockup:
		return "Operating system lockup or power interrupt"
	case sensorBootFailure:
		return "System boot failure"
	case sensorFirmwareStart:
		return "System firmware started (at least one CPU is properly executing)."
	default:
		return fmt.Sprintf("Unknown Sensor Type #%d", sensorType)
	}
}

// firmwareName renders a firmware record: an error at offset 0, otherwise how
// far the boot got.
func firmwareName(eventOffset uint8, data [8]uint8) string {
	if data[0] == invalidFirmwareData {
		return "Invalid Data"
	}

	bootErrors := []string{
		"Unspecified.",
		"No system memory is physically installed in the system.",
		"No usable system memory, all installed memory has experienced an unrecoverable failure.",
		"Unrecoverable hard-disk/ATAPI/IDE device failure.",
		"Unrecoverable system-board failure.",
		"Unrecoverable diskette subsystem failure.",
		"Unrecoverable hard-disk controller failure.",
		"Unrecoverable PS/2 or USB keyboard failure.",
		"Removable boot media not found.",
		"Unrecoverable video controller failure.",
		"No video device detected.",
		"Firmware (BIOS) ROM corruption detected.",
		"CPU voltage mismatch (processors that share same supply have mismatched voltage requirements)",
		"CPU speed matching failure",
	}
	bootProgress := []string{
		"Unspecified.",
		"Memory initialization.",
		"Starting hard-disk initialization and test",
		"Secondary processor(s) initialization",
		"User authentication",
		"User-initiated system setup",
		"USB resource configuration",
		"PCI resource configuration",
		"Option ROM initialization",
		"Video initialization",
		"Cache initialization",
		"SM Bus initialization",
		"Keyboard controller initialization",
		"Embedded controller/management controller initialization",
		"Docking station attachment",
		"Enabling docking station",
		"Docking station ejection",
		"Disabling docking station",
		"Calling operating system wake-up vector",
		"Starting operating system boot process",
		"Baseboard or motherboard initialization",
		"reserved",
		"Floppy initialization",
		"Keyboard test",
		"Pointing device test",
		"Primary processor initialization",
	}

	if eventOffset == 0 {
		return lookup(bootErrors, data[1])
	}

	return lookup(bootProgress, data[1])
}

// watchdogName renders a watchdog record: the leading bytes of the agent's UUID
// and the state it moved to.
func watchdogName(data [8]uint8) string {
	if data[0] != watchdogAgent {
		return "Unknown event data field"
	}

	states := map[uint8]string{
		1:  "Not Started",
		2:  "Stopped",
		4:  "Running",
		8:  "Expired",
		16: "Suspended",
	}

	// The UUID is little-endian, hence the reversed halves.
	agent := fmt.Sprintf("%x%x%x%x-%x%x", data[4], data[3], data[2], data[1], data[6], data[5])

	return fmt.Sprintf("Agent watchdog %s-... changed to %s", agent, states[data[7]])
}

// severityName renders the EventSeverity byte, whose values are one bit each.
func severityName(severity uint8) string {
	names := map[uint8]string{
		0:  "Unspecified",
		1:  "Monitor",
		2:  "Information",
		4:  "OK",
		8:  "Non-critical condition",
		16: "Critical condition",
		32: "Non-recoverable condition",
	}

	return names[severity]
}

// entityName renders the Entity byte, the part of the machine that reported.
func entityName(entity uint8) string {
	names := []string{
		"Unspecified", "Other", "Unknown", "Processor", "Disk", "Peripheral",
		"System management module", "System board", "Memory module",
		"Processor module", "Power supply", "Add in card", "Front panel board",
		"Back panel board", "Power system board", "Drive backplane",
		"System internal expansion board", "Other system board", "Processor board",
		"Power unit", "Power module", "Power management board",
		"Chassis back panel board", "System chassis", "Sub chassis",
		"Other chassis board", "Disk drive bay", "Peripheral bay", "Device bay",
		"Fan cooling", "Cooling unit", "Cable interconnect", "Memory device",
		"System management software", "BIOS", "Intel(r) ME", "System bus", "Group",
		"Intel(r) ME", "External environment", "Battery", "Processing blade",
		"Connectivity switch", "Processor/memory module", "I/O module",
		"Processor I/O module", "Management controller firmware", "IPMI channel",
		"PCI bus", "PCI express bus", "SCSI bus", "SATA/SAS bus",
		"Processor front side bus",
	}

	return lookup(names, entity)
}

// lookup indexes a table that runs from 0, reporting "" past its end the way
// AMT's own tooling does.
func lookup(names []string, index uint8) string {
	if int(index) >= len(names) {
		return ""
	}

	return names[index]
}
