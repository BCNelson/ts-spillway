package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePorts_SinglePort(t *testing.T) {
	ports, err := parsePorts("8080")
	require.NoError(t, err)
	assert.Equal(t, []int{8080}, ports)
}

func TestParsePorts_Range(t *testing.T) {
	ports, err := parsePorts("8000-8003")
	require.NoError(t, err)
	assert.Equal(t, []int{8000, 8001, 8002, 8003}, ports)
}

func TestParsePorts_SinglePortRange(t *testing.T) {
	ports, err := parsePorts("9000-9000")
	require.NoError(t, err)
	assert.Equal(t, []int{9000}, ports)
}

func TestParsePorts_InvalidSinglePort(t *testing.T) {
	_, err := parsePorts("abc")
	require.Error(t, err)
}

func TestParsePorts_InvalidRangeStart(t *testing.T) {
	_, err := parsePorts("abc-9000")
	require.Error(t, err)
}

func TestParsePorts_InvalidRangeEnd(t *testing.T) {
	_, err := parsePorts("8000-xyz")
	require.Error(t, err)
}

func TestParsePorts_StartGreaterThanEnd(t *testing.T) {
	_, err := parsePorts("9000-8000")
	require.Error(t, err)
}

func TestParsePorts_RangeTooLarge(t *testing.T) {
	_, err := parsePorts("1000-3000")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too large")
}

func TestParsePorts_MaxRange(t *testing.T) {
	// 1000 is the max range (end - start)
	ports, err := parsePorts("8000-9000")
	require.NoError(t, err)
	assert.Len(t, ports, 1001)
}
