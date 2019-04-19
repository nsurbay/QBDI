/*
 * This file is part of QBDI.
 *
 * Copyright 2017 Quarkslab
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "Platform.h"
#include "Errors.h"
#include "VM_C.h"
#include "VM.h"
#include "Utility/LogSys.h"

namespace QBDI {

void qbdi_initVM(VMInstanceRef* instance, const char* cpu, const char** mattrs) {
    RequireAction("VM_C::initVM", instance, return);

    *instance = nullptr;
    std::string cpuStr = "";
    std::vector<std::string> mattrsStr;

    if(cpu != nullptr) {
        cpuStr += cpu;
    }

    if(mattrs != nullptr) {
        for(unsigned i = 0; mattrs[i] != nullptr; i++) {
            mattrsStr.push_back(std::string(mattrs[i]));
        }
    }

    *instance = (VMInstanceRef) new VM(cpuStr, mattrsStr);
}


void qbdi_terminateVM(VMInstanceRef instance) {
    RequireAction("VM_C::terminateVM", instance, return);
    delete (VM*) instance;
}

bool qbdi_getEnableAddrRet(VMInstanceRef instance) {
    RequireAction("VM_C::getEnableAddrRet", instance, return false);
    return ((VM*)instance)->getEnableAddrRet();
}

void qbdi_setEnableAddrRet(VMInstanceRef instance, bool enable) {
    RequireAction("VM_C::setEnableAddrRet", instance, return);
    ((VM*)instance)->setEnableAddrRet(enable);
}

void qbdi_addExecBrokerNoRetAddr(VMInstanceRef instance, rword addr) {
    RequireAction("VM_C::setEnableAddrRet", instance, return);
    ((VM*)instance)->addExecBrokerNoRetAddr(addr);
}

void qbdi_removeExecBrokerNoRetAddr(VMInstanceRef instance, rword addr) {
    RequireAction("VM_C::setEnableAddrRet", instance, return);
    ((VM*)instance)->removeExecBrokerNoRetAddr(addr);
}

rword qbdi_getExecBrokerReturnAddress(VMInstanceRef instance) {
    RequireAction("VM_C::getExecBrokerReturnAddress", instance, return 0);
    return ((VM*)instance)->getExecBrokerReturnAddress();
}

rword qbdi_addTrampolineCB(VMInstanceRef instance, InstCallback cbk, void* data) {
    RequireAction("VM_C::getExecBrokerReturnAddress", instance, return 0);
    return ((VM*)instance)->addTrampolineCB(cbk, data);
}

void qbdi_removeTrampolineCB(VMInstanceRef instance, rword addr) {
    RequireAction("VM_C::getExecBrokerReturnAddress", instance, return);
    ((VM*)instance)->removeTrampolineCB(addr);
}

void qbdi_addInstrumentedRange(VMInstanceRef instance, rword start, rword end) {
    RequireAction("VM_C::addInstrumentedRange", instance, return);
    ((VM*)instance)->addInstrumentedRange(start, end);
}

bool qbdi_addInstrumentedModule(VMInstanceRef instance, const char* name) {
    RequireAction("VM_C::addInstrumentedModule", instance, return false);
    return ((VM*)instance)->addInstrumentedModule(std::string(name));
}

bool qbdi_addInstrumentedModuleFromAddr(VMInstanceRef instance, rword addr) {
    RequireAction("VM_C::addInstrumentedModuleFromAddr", instance, return false);
    return ((VM*)instance)->addInstrumentedModuleFromAddr(addr);
}

bool qbdi_instrumentAllExecutableMaps(VMInstanceRef instance) {
    RequireAction("VM_C::instrumentAllExecutableMaps", instance, return false);
    return ((VM*)instance)->instrumentAllExecutableMaps();
}

bool qbdi_isInstrumented(VMInstanceRef instance, rword addr) {
    RequireAction("VM_C::isInstrumented", instance, return false);
    return ((VM*)instance)->isInstrumented(addr);
}

void qbdi_removeInstrumentedRange(VMInstanceRef instance, rword start, rword end) {
    RequireAction("VM_C::removeInstrumentedRange", instance, return);
    ((VM*)instance)->removeInstrumentedRange(start, end);
}

void qbdi_removeAllInstrumentedRanges(VMInstanceRef instance) {
    RequireAction("VM_C::removeAllInstrumentedRanges", instance, return);
    ((VM*)instance)->removeAllInstrumentedRanges();
}

bool qbdi_removeInstrumentedModule(VMInstanceRef instance, const char* name) {
    RequireAction("VM_C::removeInstrumentedModule", instance, return false);
    return ((VM*)instance)->removeInstrumentedModule(std::string(name));
}

bool qbdi_removeInstrumentedModuleFromAddr(VMInstanceRef instance, rword addr) {
    RequireAction("VM_C::removeInstrumentedModuleFromAddr", instance, return false);
    return ((VM*)instance)->removeInstrumentedModuleFromAddr(addr);
}

bool qbdi_run(VMInstanceRef instance, rword start, rword stop) {
    RequireAction("VM_C::run", instance, return false);
    return ((VM*) instance)->run(start, stop);
}

bool qbdi_call(VMInstanceRef instance, rword* retval, rword function, uint32_t argNum, ...) {
    RequireAction("VM_C::call", instance, return false);
    va_list ap;
    va_start(ap, argNum);
    bool res = ((VM*) instance)->callV(retval, function, argNum, ap);
    va_end(ap);
    return res;
}

bool qbdi_callV(VMInstanceRef instance, rword* retval, rword function, uint32_t argNum, va_list ap) {
    RequireAction("VM_C::callV", instance, return false);
    return ((VM*) instance)->callV(retval, function, argNum, ap);
}

bool qbdi_callA(VMInstanceRef instance, rword* retval, rword function, uint32_t argNum, const rword* args) {
    RequireAction("VM_C::callA", instance, return false);
    return ((VM*) instance)->callA(retval, function, argNum, args);
}

GPRState* qbdi_getGPRState(VMInstanceRef instance) {
    RequireAction("VM_C::getGPRState", instance, return nullptr);
    return ((VM*) instance)->getGPRState();
}

FPRState* qbdi_getFPRState(VMInstanceRef instance) {
    RequireAction("VM_C::getFPRState", instance, return nullptr);
    return ((VM*) instance)->getFPRState();
}

void qbdi_setGPRState(VMInstanceRef instance, GPRState* gprState) {
    RequireAction("VM_C::setGPRState", instance, return);
    ((VM*) instance)->setGPRState(gprState);
}

void qbdi_setFPRState(VMInstanceRef instance, FPRState* gprState) {
    RequireAction("VM_C::setFPRState", instance, return);
    ((VM*) instance)->setFPRState(gprState);
}

uint32_t qbdi_addMnemonicCB(VMInstanceRef instance, const char* mnemonic, InstPosition pos, InstCallback cbk, void *data) {
    RequireAction("VM_C::addMnemonicCB", instance, return VMError::INVALID_EVENTID);
    return ((VM*) instance)->addMnemonicCB(mnemonic, pos, cbk, data);
}

uint32_t qbdi_addCodeCB(VMInstanceRef instance, InstPosition pos, InstCallback cbk, void *data) {
    RequireAction("VM_C::addCodeCB", instance, return VMError::INVALID_EVENTID);
    return ((VM*) instance)->addCodeCB(pos, cbk, data);
}

uint32_t qbdi_addCodeAddrCB(VMInstanceRef instance, rword address, InstPosition pos, InstCallback cbk, void *data) {
    RequireAction("VM_C::addCodeAddrCB", instance, return VMError::INVALID_EVENTID);
    return ((VM*) instance)->addCodeAddrCB(address, pos, cbk, data);
}

uint32_t qbdi_addCodeRangeCB(VMInstanceRef instance, rword start, rword end, InstPosition pos, InstCallback cbk, void *data) {
    RequireAction("VM_C::addCodeRangeCB", instance, return VMError::INVALID_EVENTID);
    return ((VM*) instance)->addCodeRangeCB(start, end, pos, cbk, data);
}

uint32_t qbdi_addMemAccessCB(VMInstanceRef instance, MemoryAccessType type, InstCallback cbk, void *data) {
    RequireAction("VM_C::addMemAccessCB", instance, return VMError::INVALID_EVENTID);
    return ((VM*) instance)->addMemAccessCB(type, cbk, data);
}

uint32_t qbdi_addMemAddrCB(VMInstanceRef instance, rword address, MemoryAccessType type, InstCallback cbk, void *data) {
    RequireAction("VM_C::addMemAddrCB", instance, return VMError::INVALID_EVENTID);
    return ((VM*) instance)->addMemAddrCB(address, type, cbk, data);
}

uint32_t qbdi_addMemRangeCB(VMInstanceRef instance, rword start, rword end, MemoryAccessType type, InstCallback cbk, void *data) {
    RequireAction("VM_C::addMemRangeCB", instance, return VMError::INVALID_EVENTID);
    return ((VM*) instance)->addMemRangeCB(start, end, type, cbk, data);
}

uint32_t qbdi_addVMEventCB(VMInstanceRef instance, VMEvent mask, VMCallback cbk, void *data) {
    RequireAction("VM_C::addVMEventCB", instance, return VMError::INVALID_EVENTID);
    return ((VM*) instance)->addVMEventCB(mask, cbk, data);
}

uint32_t qbdi_addExecBrokerCB(VMInstanceRef instance, rword start, rword end, VMCallback cbk, void *data) {
    RequireAction("VM_C::addVMEventCB", instance, return VMError::INVALID_EVENTID);
    return ((VM*) instance)->addExecBrokerCB(start, end, cbk, data);
}

uint32_t qbdi_addExecBrokerAddrCB(VMInstanceRef instance, rword addr, VMCallback cbk, void *data) {
    RequireAction("VM_C::addVMEventCB", instance, return VMError::INVALID_EVENTID);
    return ((VM*) instance)->addExecBrokerCB(addr, addr + 1, cbk, data);
}

bool qbdi_deleteInstrumentation(VMInstanceRef instance, uint32_t id) {
    RequireAction("VM_C::deleteInstrumentation", instance, return false);
    return ((VM*) instance)->deleteInstrumentation(id);
}

void qbdi_deleteAllInstrumentations(VMInstanceRef instance) {
    RequireAction("VM_C::deleteAllInstrumentations", instance, return);
    ((VM*) instance)->deleteAllInstrumentations();
}

const InstAnalysis* qbdi_getInstAnalysis(VMInstanceRef instance, AnalysisType type) {
    RequireAction("VM_C::getInstAnalysis", instance, return nullptr);
    return ((VM*) instance)->getInstAnalysis(type);
}

bool qbdi_recordMemoryAccess(VMInstanceRef instance, MemoryAccessType type) {
    RequireAction("VM_C::recordMemoryAccess", instance, return false);
    return ((VM*) instance)->recordMemoryAccess(type);
}

MemoryAccess* qbdi_getInstMemoryAccess(VMInstanceRef instance, size_t* size) {
    RequireAction("VM_C::getInstMemoryAccess", instance, return nullptr);
    RequireAction("VM_C::getInstMemoryAccess", size, return nullptr);
    *size = 0;
    std::vector<MemoryAccess> ma_vec = ((VM*) instance)->getInstMemoryAccess();
    // Do not allocate if no shadows
    if(ma_vec.size() == 0) {
        return NULL;
    }
    // Allocate and copy
    *size = ma_vec.size();
    MemoryAccess* ma_arr = (MemoryAccess*) malloc(*size * sizeof(MemoryAccess));
    for(size_t i = 0; i < *size; i++) {
        ma_arr[i] = ma_vec[i];
    }
    return ma_arr;
}

MemoryAccess* qbdi_getBBMemoryAccess(VMInstanceRef instance, size_t* size) {
    RequireAction("VM_C::getBBMemoryAccess", instance, return nullptr);
    RequireAction("VM_C::getBBMemoryAccess", size, return nullptr);
    *size = 0;
    std::vector<MemoryAccess> ma_vec = ((VM*) instance)->getBBMemoryAccess();
    // Do not allocate if no shadows
    if(ma_vec.size() == 0) {
        return NULL;
    }
    // Allocate and copy
    *size = ma_vec.size();
    MemoryAccess* ma_arr = (MemoryAccess*) malloc(*size * sizeof(MemoryAccess));
    for(size_t i = 0; i < *size; i++) {
        ma_arr[i] = ma_vec[i];
    }
    return ma_arr;
}

bool qbdi_precacheBasicBlock(VMInstanceRef instance, rword pc) {
    RequireAction("VM_C::precacheBasicBlock", instance, return false);
    return ((VM*) instance)->precacheBasicBlock(pc);
}

void qbdi_clearAllCache(VMInstanceRef instance) {
    ((VM*) instance)->clearAllCache();
}

void qbdi_clearCache(VMInstanceRef instance, rword start, rword end) {
    ((VM*) instance)->clearCache(start, end);
}

}
