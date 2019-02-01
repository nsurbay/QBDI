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
#ifndef EXECBROKER_H
#define EXECBROKER_H

#include <string>

#include "llvm/Support/Process.h"

#include "Memory.h"
#include "Range.h"
#include "State.h"
#include "ExecBlock/ExecBlock.h"
#include "Patch/Trampoline.h"
#include "Utility/Assembly.h"
#include "Utility/LogSys.h"

namespace QBDI {

struct CallbackTrampoline {
    rword           addr;
    bool            internal;
    bool            used;
    union {
        struct {
            InstCallback    cbk;
            void*           data;
        } cb;
        struct {
            rword   originReturnAddr;
            rword   addrReturnAddr;
        } data;
    };


};


class ExecBroker {

private:
    
    bool                   enableRetAddr = true;
    // address where RetAddr is disable
    std::vector<CallbackTrampoline> trampolineCallBacks;
    std::set<rword>        noRetAddr;
    RangeSet<rword>        instrumented;
    ExecBlock              transferBlock;
    rword                  pageSize;
    llvm::MCInstrInfo&     MCII;
    llvm::MCRegisterInfo&  MRI;
    VMInstanceRef          vminstance;

    using PF = llvm::sys::Memory::ProtectionFlags;

    // ARCH dependant method
    rword *getReturnPoint(GPRState* gprState) const;
    struct CallbackTrampoline* getTrampoline();

public:

    ExecBroker(Assembly& assembly, VMInstanceRef vminstance, llvm::MCInstrInfo& MCII, llvm::MCRegisterInfo& MRI);

    bool isInstrumented(rword addr) const { return instrumented.contains(addr);}

    bool getEnableAddrRet() const { return enableRetAddr;}
    void setEnableAddrRet(bool enable) { enableRetAddr = enable;}
    
    void addNoRetAddr(rword addr);
    void removeNoRetAddr(rword addr);

    rword getReturnAddress();
    rword addTrampolineCB(InstCallback cbk, void* data);
    void removeTrampolineCB(rword addr);

    void addInstrumentedRange(const Range<rword>& r);
    bool addInstrumentedModule(const std::string& name);
    bool addInstrumentedModuleFromAddr(rword addr);
    
    void removeInstrumentedRange(const Range<rword>& r);
    bool removeInstrumentedModule(const std::string& name);
    bool removeInstrumentedModuleFromAddr(rword addr);
    void removeAllInstrumentedRanges();

    bool instrumentAllExecutableMaps();

    bool canTransferExecution(GPRState* gprState) const;

    bool transferExecution(rword addr, GPRState *gprState, FPRState *fprState);
};

}

#endif // EXECBROKER_H
