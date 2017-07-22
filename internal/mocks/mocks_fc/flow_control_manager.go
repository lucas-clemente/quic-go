// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/lucas-clemente/quic-go/flowcontrol (interfaces: FlowControlManager)

package mocks_fc

import (
	gomock "github.com/golang/mock/gomock"
	flowcontrol "github.com/lucas-clemente/quic-go/flowcontrol"
	protocol "github.com/lucas-clemente/quic-go/protocol"
	reflect "reflect"
)

// MockFlowControlManager is a mock of FlowControlManager interface
type MockFlowControlManager struct {
	ctrl     *gomock.Controller
	recorder *MockFlowControlManagerMockRecorder
}

// MockFlowControlManagerMockRecorder is the mock recorder for MockFlowControlManager
type MockFlowControlManagerMockRecorder struct {
	mock *MockFlowControlManager
}

// NewMockFlowControlManager creates a new mock instance
func NewMockFlowControlManager(ctrl *gomock.Controller) *MockFlowControlManager {
	mock := &MockFlowControlManager{ctrl: ctrl}
	mock.recorder = &MockFlowControlManagerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (_m *MockFlowControlManager) EXPECT() *MockFlowControlManagerMockRecorder {
	return _m.recorder
}

// AddBytesRead mocks base method
func (_m *MockFlowControlManager) AddBytesRead(_param0 protocol.StreamID, _param1 protocol.ByteCount) error {
	ret := _m.ctrl.Call(_m, "AddBytesRead", _param0, _param1)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddBytesRead indicates an expected call of AddBytesRead
func (_mr *MockFlowControlManagerMockRecorder) AddBytesRead(arg0, arg1 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "AddBytesRead", reflect.TypeOf((*MockFlowControlManager)(nil).AddBytesRead), arg0, arg1)
}

// AddBytesSent mocks base method
func (_m *MockFlowControlManager) AddBytesSent(_param0 protocol.StreamID, _param1 protocol.ByteCount) error {
	ret := _m.ctrl.Call(_m, "AddBytesSent", _param0, _param1)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddBytesSent indicates an expected call of AddBytesSent
func (_mr *MockFlowControlManagerMockRecorder) AddBytesSent(arg0, arg1 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "AddBytesSent", reflect.TypeOf((*MockFlowControlManager)(nil).AddBytesSent), arg0, arg1)
}

// GetReceiveWindow mocks base method
func (_m *MockFlowControlManager) GetReceiveWindow(_param0 protocol.StreamID) (protocol.ByteCount, error) {
	ret := _m.ctrl.Call(_m, "GetReceiveWindow", _param0)
	ret0, _ := ret[0].(protocol.ByteCount)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetReceiveWindow indicates an expected call of GetReceiveWindow
func (_mr *MockFlowControlManagerMockRecorder) GetReceiveWindow(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "GetReceiveWindow", reflect.TypeOf((*MockFlowControlManager)(nil).GetReceiveWindow), arg0)
}

// GetWindowUpdates mocks base method
func (_m *MockFlowControlManager) GetWindowUpdates() []flowcontrol.WindowUpdate {
	ret := _m.ctrl.Call(_m, "GetWindowUpdates")
	ret0, _ := ret[0].([]flowcontrol.WindowUpdate)
	return ret0
}

// GetWindowUpdates indicates an expected call of GetWindowUpdates
func (_mr *MockFlowControlManagerMockRecorder) GetWindowUpdates() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "GetWindowUpdates", reflect.TypeOf((*MockFlowControlManager)(nil).GetWindowUpdates))
}

// NewStream mocks base method
func (_m *MockFlowControlManager) NewStream(_param0 protocol.StreamID, _param1 bool) {
	_m.ctrl.Call(_m, "NewStream", _param0, _param1)
}

// NewStream indicates an expected call of NewStream
func (_mr *MockFlowControlManagerMockRecorder) NewStream(arg0, arg1 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "NewStream", reflect.TypeOf((*MockFlowControlManager)(nil).NewStream), arg0, arg1)
}

// RemainingConnectionWindowSize mocks base method
func (_m *MockFlowControlManager) RemainingConnectionWindowSize() protocol.ByteCount {
	ret := _m.ctrl.Call(_m, "RemainingConnectionWindowSize")
	ret0, _ := ret[0].(protocol.ByteCount)
	return ret0
}

// RemainingConnectionWindowSize indicates an expected call of RemainingConnectionWindowSize
func (_mr *MockFlowControlManagerMockRecorder) RemainingConnectionWindowSize() *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "RemainingConnectionWindowSize", reflect.TypeOf((*MockFlowControlManager)(nil).RemainingConnectionWindowSize))
}

// RemoveStream mocks base method
func (_m *MockFlowControlManager) RemoveStream(_param0 protocol.StreamID) {
	_m.ctrl.Call(_m, "RemoveStream", _param0)
}

// RemoveStream indicates an expected call of RemoveStream
func (_mr *MockFlowControlManagerMockRecorder) RemoveStream(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "RemoveStream", reflect.TypeOf((*MockFlowControlManager)(nil).RemoveStream), arg0)
}

// ResetStream mocks base method
func (_m *MockFlowControlManager) ResetStream(_param0 protocol.StreamID, _param1 protocol.ByteCount) error {
	ret := _m.ctrl.Call(_m, "ResetStream", _param0, _param1)
	ret0, _ := ret[0].(error)
	return ret0
}

// ResetStream indicates an expected call of ResetStream
func (_mr *MockFlowControlManagerMockRecorder) ResetStream(arg0, arg1 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "ResetStream", reflect.TypeOf((*MockFlowControlManager)(nil).ResetStream), arg0, arg1)
}

// SendWindowSize mocks base method
func (_m *MockFlowControlManager) SendWindowSize(_param0 protocol.StreamID) (protocol.ByteCount, error) {
	ret := _m.ctrl.Call(_m, "SendWindowSize", _param0)
	ret0, _ := ret[0].(protocol.ByteCount)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// SendWindowSize indicates an expected call of SendWindowSize
func (_mr *MockFlowControlManagerMockRecorder) SendWindowSize(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "SendWindowSize", reflect.TypeOf((*MockFlowControlManager)(nil).SendWindowSize), arg0)
}

// UpdateHighestReceived mocks base method
func (_m *MockFlowControlManager) UpdateHighestReceived(_param0 protocol.StreamID, _param1 protocol.ByteCount) error {
	ret := _m.ctrl.Call(_m, "UpdateHighestReceived", _param0, _param1)
	ret0, _ := ret[0].(error)
	return ret0
}

// UpdateHighestReceived indicates an expected call of UpdateHighestReceived
func (_mr *MockFlowControlManagerMockRecorder) UpdateHighestReceived(arg0, arg1 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "UpdateHighestReceived", reflect.TypeOf((*MockFlowControlManager)(nil).UpdateHighestReceived), arg0, arg1)
}

// UpdateWindow mocks base method
func (_m *MockFlowControlManager) UpdateWindow(_param0 protocol.StreamID, _param1 protocol.ByteCount) (bool, error) {
	ret := _m.ctrl.Call(_m, "UpdateWindow", _param0, _param1)
	ret0, _ := ret[0].(bool)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// UpdateWindow indicates an expected call of UpdateWindow
func (_mr *MockFlowControlManagerMockRecorder) UpdateWindow(arg0, arg1 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCall(_mr.mock, "UpdateWindow", reflect.TypeOf((*MockFlowControlManager)(nil).UpdateWindow), arg0, arg1)
}
