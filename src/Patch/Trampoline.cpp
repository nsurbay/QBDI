/*
 * This file is part of QBDI.
 *
 * Copyright 2019 Quarkslab
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

#include "Patch/Trampoline.h"

namespace QBDI {

std::vector<Patch> getExecbrokerTrampoline(rword id, llvm::MCInstrInfo* MCII, llvm::MCRegisterInfo* MRI) {
    std::vector<Patch> ret;
    Patch p;
    llvm::MCInst nop;
    PatchGenerator::SharedPtrVec callbackGenerator;

    // setup NOP instruction
    nop.setOpcode(llvm::X86::NOOP);

    // create Patch empty with supposed instruction NOP
    p = Patch(nop, 0, nop.size());
    p.metadata.instSize = 0;

    // Create instrumentation to save registre
    callbackGenerator.push_back(GetConstant(Temp(0), Constant(id)));
    callbackGenerator.push_back(WriteTemp(Temp(0), Offset(offsetof(Context, hostState.callback))));

    // Apply instrumentation and instrument
    InstrRule(True(), callbackGenerator, InstPosition::PREINST, false).instrument(p, MCII, MRI);

    // add Patch in vector and return
    ret.push_back(p);
    return ret;
}


}
