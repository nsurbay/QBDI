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
#include "ExecBroker/ExecBroker.h" 

namespace QBDI {

ExecBroker::ExecBroker(Assembly& assembly, VMInstanceRef vminstance, llvm::MCInstrInfo& MCII, llvm::MCRegisterInfo& MRI) :
    transferBlock(assembly, vminstance), MCII(MCII), MRI(MRI), vminstance(vminstance) {
    pageSize = llvm::sys::Process::getPageSize();
}

rword ExecBroker::getReturnAddress() {
    return transferBlock.getCurrentPC() + transferBlock.getEpilogueOffset();
}

void ExecBroker::addNoRetAddr(rword addr) {
    noRetAddr.insert(addr);
}

void ExecBroker::removeNoRetAddr(rword addr) {
    noRetAddr.erase(addr);
}

rword ExecBroker::addTrampolineCB(InstCallback cbk, void* data){
    struct CallbackTrampoline* res = getTrampoline();
    if (res == NULL) {
        return 0;
    }
    res->internal = false;
    res->cb.cbk = cbk;
    res->cb.data = data;
    
    return res->addr;
}

struct CallbackTrampoline* ExecBroker::getTrampoline(){
    for (size_t i = 0; i < trampolineCallBacks.size(); i++) {
        if (!trampolineCallBacks[i].used) {
            trampolineCallBacks[i].used = true;
            LogDebug("ExecBroker::getTrampoline", "Found available trampoline at 0x%" PRIRWORD, trampolineCallBacks[i].addr);

            return &trampolineCallBacks[i];
        }
    }
    rword addrTrampoline = transferBlock.getCurrentPC();
    std::vector<Patch> patchvect = getExecbrokerTrampoline(addrTrampoline, &MCII, &MRI);
    
    SeqWriteResult writeRes = transferBlock.writeSequence(patchvect.begin(), patchvect.end(), SeqType::Exit);
    if (writeRes.seqID == EXEC_BLOCK_FULL) {
        LogDebug("ExecBroker::getTrampoline", "No Free Space available");
        return NULL;
    }
    trampolineCallBacks.push_back( CallbackTrampoline {addrTrampoline, false, true});
    LogDebug("ExecBroker::getTrampoline", "Create new Trampoline at 0x%" PRIRWORD, addrTrampoline);
    return &trampolineCallBacks[trampolineCallBacks.size() - 1];
}

void ExecBroker::removeTrampolineCB(rword addr){
    for (size_t i = 0; i < trampolineCallBacks.size(); i++) {
        if (trampolineCallBacks[i].addr == addr && trampolineCallBacks[i].internal == false) {
            trampolineCallBacks[i].used = false;
            return;
        }
    }
}

void ExecBroker::addInstrumentedRange(const Range<rword>& r) {
    LogDebug("ExecBroker::addInstrumentedRange", "Adding instrumented range [%" PRIRWORD ", %" PRIRWORD "]", 
             r.start, r.end);
    instrumented.add(r);
}

void ExecBroker::removeInstrumentedRange(const Range<rword>& r) {
    LogDebug("ExecBroker::removeInstrumentedRange", "Removing instrumented range [%" PRIRWORD ", %" PRIRWORD "]", 
             r.start, r.end);
    instrumented.remove(r);
}

void ExecBroker::removeAllInstrumentedRanges() {
    instrumented.clear();
}

bool ExecBroker::addInstrumentedModule(const std::string& name) {
    bool instrumented = false;
    if (name.empty()) {
        return false;
    }

    for(const MemoryMap& m : getCurrentProcessMaps()) {
        if((m.name == name) && (m.permission & QBDI::PF_EXEC)) {
            addInstrumentedRange(m.range);
            instrumented = true;
        }
    }
    return instrumented;
}

bool ExecBroker::addInstrumentedModuleFromAddr(rword addr) {
    bool instrumented = false;

    for(const MemoryMap& m : getCurrentProcessMaps()) {
        if(m.range.contains(addr)) {
            instrumented = addInstrumentedModule(m.name);
            break;
        }
    }
    return instrumented;
}

bool ExecBroker::removeInstrumentedModule(const std::string& name) {
    bool removed = false;

    for(const MemoryMap& m : getCurrentProcessMaps()) {
        if((m.name == name) && (m.permission & QBDI::PF_EXEC)) {
            removeInstrumentedRange(m.range);
            removed = true;
        }
    }
    return removed;
}

bool ExecBroker::removeInstrumentedModuleFromAddr(rword addr) {
    bool removed = false;

    for(const MemoryMap& m : getCurrentProcessMaps()) {
        if(m.range.contains(addr)) {
            removed = removeInstrumentedModule(m.name);
            break;
        }
    }
    return removed;
}

bool ExecBroker::instrumentAllExecutableMaps() {
    bool instrumented = false;

    for(const MemoryMap& m : getCurrentProcessMaps()) {
        if(m.permission & QBDI::PF_EXEC) {
            addInstrumentedRange(m.range);
            instrumented = true;
        }
    }
    return instrumented;
}

bool ExecBroker::canTransferExecution(GPRState *gprState) const {
    return (!enableRetAddr || getReturnPoint(gprState) || noRetAddr.find(QBDI_GPR_GET(gprState, REG_PC)) != noRetAddr.end());
}

bool ExecBroker::transferExecution(rword addr, GPRState *gprState, FPRState *fprState) {
    rword *ptr = NULL;

    ptr = getReturnPoint(gprState);
    if (enableRetAddr && noRetAddr.find(QBDI_GPR_GET(gprState, REG_PC)) == noRetAddr.end()) {
        if (!ptr)
            return false;
    
        // Backup / Patch return address
        struct CallbackTrampoline* tramp = getTrampoline();
        tramp->internal = true;
        tramp->data.originReturnAddr = *ptr;
        tramp->data.addrReturnAddr = (rword) ptr;
        *ptr = tramp->addr;
        LogDebug("ExecBroker::transferExecution", "Patched %p hooking return address 0x%" PRIRWORD " with 0x%" PRIRWORD, 
                 ptr, tramp->data.originReturnAddr, *ptr);
    }

    // Write transfer state
    transferBlock.getContext()->gprState = *gprState;
    transferBlock.getContext()->fprState = *fprState;
    transferBlock.getContext()->hostState.selector = addr;
    transferBlock.getContext()->hostState.callback = 0;
    // Execute transfer
    LogDebug("ExecBroker::transferExecution", "Transfering execution to 0x%" PRIRWORD " using transferBlock %p", addr, &transferBlock);
    transferBlock.run(true);
    // Read transfer result
    *gprState = transferBlock.getContext()->gprState;
    *fprState = transferBlock.getContext()->fprState;

    // Search Trampoline
    if (transferBlock.getContext()->hostState.callback != 0) {
        rword id = transferBlock.getContext()->hostState.callback;
        bool found = false;
        for (size_t i = 0; i < trampolineCallBacks.size(); i++) {
            if (trampolineCallBacks[i].used && trampolineCallBacks[i].addr == id) {
                struct CallbackTrampoline* tramp = &trampolineCallBacks[i];
                found = true;
                if (tramp->internal) {
                    LogDebug("ExecBroker::transferExecution", "Trampoline 0x%lx trigger, replace original return addr 0x%lx",
                            tramp->data.originReturnAddr);
                    QBDI_GPR_SET(gprState, REG_PC, tramp->data.originReturnAddr);
                    #if defined(QBDI_ARCH_ARM)
                    // Under ARM, also reset the LR register
                    if(QBDI_GPR_GET(gprState, REG_LR) == tramp->addr) {
                        QBDI_GPR_SET(gprState, REG_LR, tramp->data.originReturnAddr);
                    }
                    #endif
                    tramp->used = false;
                } else {
                    LogDebug("ExecBroker::transferExecution", "Trampoline 0x%lx trigger, called associated callback (0x%" PRIRWORD")",
                            id, tramp->cb.cbk);
                    tramp->cb.cbk(vminstance, gprState, fprState, tramp->cb.data);
                    LogDebug("ExecBroker::transferExecution", "End of Callback (0x%" PRIRWORD")",
                            tramp->cb.cbk);
                }
                break;
            }
        }
        if (!found) {
            LogDebug("ExecBroker::transferExecution", "Any trampoline match id 0x%lx", id);
        }
    } else {
        LogDebug("ExecBroker::transferExecution", "Return without trampoline, may not append");
    }
    //else if (enableRetAddr && noRetAddr.find(QBDI_GPR_GET(gprState, REG_PC)) == noRetAddr.end() && hookedAddress != 0) {
    //    // Restore original return
    //    QBDI_GPR_SET(&transferBlock.getContext()->gprState, REG_PC, hookedAddress);
    //    #if defined(QBDI_ARCH_ARM)
    //    // Under ARM, also reset the LR register
    //    if(QBDI_GPR_GET(&transferBlock.getContext()->gprState, REG_LR) == hook) {
    //        QBDI_GPR_SET(&transferBlock.getContext()->gprState, REG_LR, hookedAddress);
    //    }
    //    #endif
    //}

    return true;
}

#if defined(QBDI_ARCH_X86_64)

rword *ExecBroker::getReturnPoint(GPRState *gprState) const {
    static int SCAN_DISTANCE = 3;
    rword *ptr = (rword*) gprState->rsp;

    for(int i = 0; i < SCAN_DISTANCE; i++) {
        if(isInstrumented(ptr[i])) {
            LogDebug("ExecBroker::getReturnPoint", "Found instrumented return address on the stack at %p", &(ptr[i]));
            return &(ptr[i]);
        }
    }
    LogDebug("ExecBroker::getReturnPoint", "No instrumented return address found on the stack");
    return NULL;
}

#elif defined(QBDI_ARCH_ARM)

rword *ExecBroker::getReturnPoint(GPRState *gprState) const {
    static int SCAN_DISTANCE = 2;
    rword *ptr = (rword*) gprState->sp;

    if(isInstrumented(gprState->lr)) {
        LogDebug("ExecBroker::getReturnPoint", "Found instrumented return address in LR register");
        return &(gprState->lr);
    }
    for(int i = 0; i < SCAN_DISTANCE; i++) {
        if(isInstrumented(ptr[i])) {
            LogDebug("ExecBroker::getReturnPoint", "Found instrumented return address on the stack at %p", &(ptr[i]));
            return &(ptr[i]);
        }
    }

    LogDebug("ExecBroker::getReturnPoint", "LR register does not contain an instrumented return address");
    return NULL;
}

#endif

}
