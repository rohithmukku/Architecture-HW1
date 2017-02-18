
/*! @file
 *  This is an example of the PIN tool that demonstrates some basic PIN APIs 
 *  and could serve as the starting point for developing your first PIN tool
 */

#include "pin.H"
#include <string>
#include <sstream>
#include <cstdint>
#include <iostream>
#include <fstream>
#include <set>
#include <vector>

using namespace std;

UINT64 fast_forward_count = 0;     //fast forward count
UINT64 insCount = 0;                    //number of dynamically executed instructions
UINT64 bblCount = 0;                    //number of dynamically executed basic blocks
UINT64 threadCount = 0;                 //total number of threads, including main thread
static UINT64 icount = 0;               //total number of Instructions
static UINT64 nopcount = 0;             //total number of NOP Instructions
static UINT64 direct_call_count = 0;    //total number of Direct Call Instructions
static UINT64 indirect_call_count = 0;  //total number of Indirect Call Instructions
static UINT64 return_count = 0;         //total number of Return Call Instructions
static UINT64 unconditional_count = 0;  //total number of Unconditional Branch Instructions
static UINT64 conditional_count = 0;    //total number of Conditional Branch Instructions
static UINT64 logical_count = 0;        //total number of Logical Operations
static UINT64 rotate_shift_count = 0;   //total number of Rotate & Shift Instructions
static UINT64 flag_call_count = 0;      //total number of Flag Operations
static UINT64 vector_count = 0;         //total number of Vector Instructions
static UINT64 moves_count = 0;          //total number of Conditional Moves
static UINT64 mmx_sse_count = 0;        //total number of MMX & SSE Instructions
static UINT64 system_call_count = 0;    //total number of System Call Instructions
static UINT64 fp_count = 0;             //total number of Floating point Instructions
static UINT64 other_count = 0;          //total number of Other Instructions
static UINT64 read_count = 0;           //total number of Read operations
static UINT64 write_count = 0;          //total number of Write operations
static UINT64 latency = 0;              //total number of cycles executed
static UINT64 executed_ins = 0;         //total number of cycles executed

std::set <ADDRINT> insAddresses;        //list of Instruction Addresses accessed
std::set <ADDRINT> dataAddresses;       //list of Data Addresses accessed

static UINT64 insArray[50];
static UINT64 Operands[50];
static UINT64 readCount[50];
static UINT64 writeCount[50];
static UINT64 maxInsLength = 0;
static UINT64 maxOpLength = 0;
static UINT64 maxRead = 0;
static UINT64 maxWrite = 0;

static UINT64 memSize[50];
static UINT64 readmemSize[50];
static UINT64 writememSize[50];
static UINT64 maxMem = 0;
static UINT64 maxMemRead = 0;
static UINT64 maxMemWrite = 0;

static INT32 maxImmediate = 0;
static INT32 minImmediate = 0;

static ADDRDELTA maxDisplacement = 0;
static ADDRDELTA minDisplacement = 0;

static UINT64 memAccessed = 0;
static UINT64 MAXmemAccessed = 0;
static UINT64 mem_op_counter = 0;

std::ostream * out = &cerr;

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,  "pintool",
    "o", "", "specify file name for MyPinTool output");

KNOB<BOOL>   KnobCount(KNOB_MODE_WRITEONCE,  "pintool",
    "count", "1", "count instructions, basic blocks and threads in the application");

KNOB<UINT64> KnobFastForward(KNOB_MODE_WRITEONCE, "pintool", 
    "f","0", "FastForward Instructions");
INT32 Usage()
{
    cerr << "This tool prints out the number of dynamically executed " << endl <<
            "instructions, basic blocks and threads in the application." << endl << endl;

    cerr << KNOB_BASE::StringKnobSummary() << endl;

    return -1;
}

void output(){
    *out <<  "============CS422: Assignment 1================" << endl;
    *out <<  "===============================================" << endl;
    *out <<  "MyPinTool analysis results: " << endl;
    *out <<  "Part-A: " << endl;
    *out <<  "Total Number of instructions: " << icount  << endl;
    *out <<  "Number of instructions executed: " << executed_ins  << endl;
    *out <<  "Number of Load Operations: " << read_count << endl;
    *out <<  "Number of Store Operations: " << write_count << endl;
    *out <<  "Number of NOP Instructions: " << nopcount << endl;
    *out <<  "Number of Direct Call Instructions: " << direct_call_count << endl;
    *out <<  "Number of Indirect Call Instructions: " << indirect_call_count << endl;
    *out <<  "Number of Return Call Instructions: " << return_count << endl;
    *out <<  "Number of Unconditional Branch Instructions: " << unconditional_count << endl;
    *out <<  "Number of Conditional Branch Instructions: " << conditional_count << endl;
    *out <<  "Number of Logical Instructions: " << logical_count << endl;
    *out <<  "Number of Rotate and Shift Instructions: " << rotate_shift_count << endl;
    *out <<  "Number of Flag Instructions: " << flag_call_count << endl;
    *out <<  "Number of Vector Instructions: " << vector_count << endl;
    *out <<  "Number of Conditional move Instructions: " << moves_count << endl;
    *out <<  "Number of MMX and SSE Instructions: " << mmx_sse_count << endl;
    *out <<  "Number of System Call Instructions: " << system_call_count << endl;
    *out <<  "Number of Floating point Instructions: " << fp_count << endl;
    *out <<  "Number of Other Instructions: " << other_count << endl;
    
    *out <<  "===============================================" << endl;
    *out <<  "Part-B: " << endl;
    *out <<  "Number of Cycles executed: " << latency << endl;
    *out <<  "CPI: " << (float)latency/executed_ins << endl;
    *out <<  "===============================================" << endl;
    *out <<  "Part-C: " << endl;
    *out <<  "Instruction Footprint: " << (insAddresses.size())*32 << endl;
    *out <<  "Data Footprint: " << (dataAddresses.size())*32 << endl;
    *out <<  "Memory Footprint: " << (insAddresses.size() + dataAddresses.size())*32 << endl;
    *out <<  "===============================================" << endl;
    *out <<  "Part-D: " << endl;
    *out <<  "1. Distribution of length instruction" << endl;
    for (UINT64 i = 0 ; i <= maxInsLength ; i++ ){
        *out <<  "Instruction length " << (i+1) << " = " <<  insArray[i] << endl;
    }
    *out <<  "2. Distribution of Number of Operands" << endl;
    for (UINT64 i = 0 ; i <= maxOpLength + 1 ; i++ ){
        *out <<  "Operands " << i << " = " <<  Operands[i] << endl;
    }
    *out <<  "3. Distribution of Register Read operations" << endl;
    for (UINT64 i = 0 ; i <= maxRead + 1 ; i++ ){
        *out <<  "Read Operations " << i << " = " <<  readCount[i] << endl;
    }
    *out <<  "4. Distribution of Register Write operations" << endl;
    for (UINT64 i = 0 ; i <= maxWrite + 1 ; i++ ){
        *out <<  "Write Operations " << i << " = " <<  writeCount[i] << endl;
    }
    *out <<  "5. Distribution of number of memory operands" << endl;
    for (UINT64 i = 0 ; i <= maxMem + 1 ; i++ ){
        *out <<  "Write Operations " << i << " = " <<  memSize[i] << endl;
    }
    for(UINT32 i =1;i <= maxMem ; i++){
        mem_op_counter += memSize[i];
    }
    *out <<  "6. Distribution of number of memory read operands" << endl;
    for (UINT64 i = 0 ; i <= maxMemRead + 1 ; i++ ){
        *out <<  "Read Operations " << i << " = " <<  readmemSize[i] << endl;
    }
    *out <<  "7. Distribution of number memory write operands" << endl;
    for (UINT64 i = 0 ; i <= maxMemWrite + 1 ; i++ ){
        *out <<  "Write Operations " << i << " = " <<  writememSize[i] << endl;
    }
    *out <<  "8. Maximum Number of memory bytes touched : "<< MAXmemAccessed << endl;
    *out <<  "8. Average Number of memory bytes touched : "<< (double) (memAccessed/mem_op_counter) << endl;

    *out <<  "9. Maximum values of the immediate field in an instruction : "<< maxImmediate << endl;
    *out <<  "9. Minimum values of the immediate field in an instruction : "<< minImmediate << endl;

    *out <<  "10. Maximum values of the displacement field : "<< maxDisplacement << endl;
    *out <<  "10. Minimum values of the displacement field : "<< minDisplacement << endl;

    *out <<  "===============================================" << endl;
    *out <<  "Number of basic blocks: " << bblCount  << endl;
    *out <<  "Number of threads: " << threadCount  << endl;
    *out <<  "===============================================" << endl;

}

void MyExitRoutine() {
    output();
    exit(0);
}

VOID CountBbl(UINT32 numInstInBbl)
{
    bblCount++;
    insCount += numInstInBbl;
}

VOID Trace(TRACE trace, VOID *v)
{
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)CountBbl, IARG_UINT32, BBL_NumIns(bbl), IARG_END);
    }
}

VOID ThreadStart(THREADID threadIndex, CONTEXT *ctxt, INT32 flags, VOID *v)
{
    threadCount++;
}

ADDRINT FastForward(void) {
    //return (icount >= fast_forward_count && icount < fast_forward_count + 1000000000);
     return (icount >= fast_forward_count && icount < fast_forward_count + 1000);
}
ADDRINT Terminate(void)
{
    // return (icount >= fast_forward_count + 1000000000);
     return (icount >= fast_forward_count + 1000);
}

VOID ins_count(){
    icount++;
}

VOID actual_ins_count(){
    executed_ins++;
}

VOID NOP_count()
{
    nopcount++;
    latency++;
}

VOID DIRECT_CALL_count()
{
    direct_call_count++;
    latency++;
}

VOID INDIRECT_CALL_count()
{
    indirect_call_count++;
    latency++;
}

VOID RETURN_count()
{
    return_count++;
    latency++;
}

VOID UNCONDITIONAL_count()
{
    unconditional_count++;
    latency++;
}

VOID CONDITIONAL_count()
{
    conditional_count++;
    latency++;
}

VOID LOGICAL_count()
{
    logical_count++;
    latency++;
}

VOID ROTATE_SHIFT_count()
{
    rotate_shift_count++;
    latency++;
}

VOID FLAG_CALL_count()
{
    flag_call_count++;
    latency++;
}

VOID VECTOR_count()
{
    vector_count++;
    latency++;
}

VOID MOVES_count()
{
    moves_count++;
    latency++;
}

VOID MMX_SSE_count()
{
    mmx_sse_count++;
    latency++;
}

VOID SYSTEM_CALL_count()
{
    system_call_count++;
    latency++;
}

VOID FP_count()
{
    fp_count++;
    latency++;
}

VOID OTHER_count()
{
    other_count++;
    latency++;
}

VOID RecordMemRead(UINT32 c){
    read_count += c;
    latency += c*50;
}

VOID RecordMemWrite(UINT32 c){
    write_count += c;
    latency += c*50;
}

VOID Operand_Size(INT32 value){
    if(value >= maxImmediate) maxImmediate = value;
    else if(value <= minImmediate) minImmediate = value;
}
VOID Memory_Displacement_Size(ADDRDELTA value){
    if (value >= maxDisplacement) maxDisplacement = value;
    else if (value <= minDisplacement) minDisplacement = value;
}

VOID DataFootprint(void *addr, UINT32 refSize){
     UINT32 dataAddress = *((UINT32*)(addr));
     UINT32 dataAddress_end  = dataAddress + refSize;
     UINT32 currAddr = (dataAddress/32)*32;
     while(currAddr < dataAddress_end)
     {
         dataAddresses.insert(currAddr);
         currAddr = currAddr + 32;
     }
}
VOID StaticAnalysis(UINT32 opSize, UINT32 readSize, UINT32 writeSize, UINT32 insSize, UINT32 insAddress){
    insArray[insSize-1]++;
    if(insSize >= maxInsLength) maxInsLength = insSize;
    
    Operands[opSize]++;
    if(opSize >= maxOpLength) maxOpLength = opSize;
    
    readCount[readSize]++;
    if(readSize >= maxRead) maxRead = readSize;
    
    writeCount[writeSize]++;
    if(writeSize >= maxWrite) maxWrite = writeSize;

    UINT32 insAddress_end  = insAddress + insSize;
    UINT32 currAddr = (insAddress/32)*32;
    while(currAddr < insAddress_end)
    {
        insAddresses.insert(currAddr);
        currAddr = currAddr + 32;
    }
}

VOID DynamicAnalysis(UINT32 memReadCount, UINT32 memWriteCount, UINT32 INSmemAccessed){
    UINT32 TotalMemOperands=(memReadCount+memWriteCount);
    memSize[TotalMemOperands]++;
    if(TotalMemOperands >= maxMem) maxMem = TotalMemOperands;

    readmemSize[memReadCount]++;
    if(memReadCount >= maxMemRead) maxMemRead = memReadCount;
    
    writememSize[memWriteCount]++;
    if(memWriteCount >= maxMemWrite) maxMemWrite = memWriteCount;

    memAccessed += INSmemAccessed;
    if(INSmemAccessed >= MAXmemAccessed) MAXmemAccessed = INSmemAccessed;
}

VOID Instructions(INS ins, VOID *v)
{
    INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR) Terminate, IARG_END);
    INS_InsertThenCall(ins, IPOINT_BEFORE,(AFUNPTR) MyExitRoutine, IARG_END);
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)ins_count, IARG_END);
    INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)FastForward, IARG_END);
    INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)actual_ins_count, IARG_END);
    UINT32 memReadCount = 0;
    UINT32 memWriteCount = 0;
    UINT32 memOperands = INS_MemoryOperandCount(ins);
    UINT32 opSize = INS_OperandCount(ins);
    UINT32 readSize = INS_MaxNumRRegs(ins);
    UINT32 writeSize = INS_MaxNumWRegs(ins);
    
    UINT32 operandCount = INS_OperandCount(ins);
    for (UINT32 op = 0; op < operandCount; op++){
        if (INS_OperandIsImmediate(ins, op)){
            ADDRINT immediateValue = INS_OperandImmediate(ins, op);
            INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)FastForward, IARG_END);
            INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)Operand_Size, IARG_ADDRINT, immediateValue,  IARG_END);        
        }
    }
    UINT32 insSize = INS_Size(ins);
    UINT32 insAddress = INS_Address(ins); 
    INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)FastForward, IARG_END);
    INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)StaticAnalysis, IARG_UINT32, opSize, IARG_UINT32, readSize, IARG_UINT32, writeSize,IARG_UINT32,insSize,IARG_UINT32,insAddress, IARG_END); 
    UINT32 INSmemAccessed = 0;
    for (UINT32 memOp = 0; memOp < memOperands; memOp++){
        UINT32 refSize = INS_MemoryOperandSize(ins, memOp);
        INSmemAccessed += refSize;
        UINT32 accesses = 0;
        if (refSize%4 == 0) accesses = refSize/4;
        else accesses = refSize/4+1;
        if (INS_MemoryOperandIsRead(ins, memOp)){
            memReadCount++;
            INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)FastForward, IARG_END);
            INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordMemRead, IARG_UINT32, accesses, IARG_END);
        }
        if (INS_MemoryOperandIsWritten(ins, memOp)){
            memWriteCount++;
            INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)FastForward, IARG_END);
            INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWrite, IARG_UINT32, accesses, IARG_END);
        }

        INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)FastForward, IARG_END);
        INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)DataFootprint, IARG_MEMORYOP_EA, memOp, IARG_UINT32, refSize, IARG_END);
        ADDRDELTA displacementValue = INS_OperandMemoryDisplacement(ins, memOp);
        INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)FastForward, IARG_END);
        INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)Memory_Displacement_Size, IARG_ADDRINT, (ADDRINT)displacementValue, IARG_END);
    }
    
    INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)FastForward, IARG_END);
    INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)DynamicAnalysis, IARG_UINT32, memReadCount, IARG_UINT32, memWriteCount, IARG_UINT32, INSmemAccessed, IARG_END);
    
    if (INS_Category(ins) == XED_CATEGORY_NOP){
        INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)FastForward, IARG_END);
        INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)NOP_count, IARG_END);
    }
    else if (INS_Category(ins) == XED_CATEGORY_CALL){
        if(INS_IsDirectCall(ins)){
            INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)FastForward, IARG_END);
            INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)DIRECT_CALL_count, IARG_END);
        }
        else{
            INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)FastForward, IARG_END);
            INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)INDIRECT_CALL_count, IARG_END);
        }
    }
    else if (INS_Category(ins) == XED_CATEGORY_RET){
        INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)FastForward, IARG_END);
        INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)UNCONDITIONAL_count, IARG_END);
    }
    else if (INS_Category(ins) == XED_CATEGORY_UNCOND_BR){
        INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)FastForward, IARG_END);
        INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)UNCONDITIONAL_count, IARG_END);
    }
    else if (INS_Category(ins) == XED_CATEGORY_COND_BR){
        INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)FastForward, IARG_END);
        INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)CONDITIONAL_count, IARG_END);
    }
    else if (INS_Category(ins) == XED_CATEGORY_LOGICAL){
        INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)FastForward, IARG_END);
        INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)LOGICAL_count, IARG_END);
    }
    else if (INS_Category(ins) == XED_CATEGORY_ROTATE || INS_Category(ins) == XED_CATEGORY_SHIFT){
        INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)FastForward, IARG_END);
        INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)ROTATE_SHIFT_count, IARG_END);
    }
    else if (INS_Category(ins) == XED_CATEGORY_FLAGOP){
        INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)FastForward, IARG_END);
        INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)FLAG_CALL_count, IARG_END);
    }
    else if (INS_Category(ins) == XED_CATEGORY_AVX || INS_Category(ins) == XED_CATEGORY_AVX2 || INS_Category(ins) == XED_CATEGORY_AVX2GATHER){
        INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)FastForward, IARG_END);
        INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)VECTOR_count, IARG_END);
    }
    else if (INS_Category(ins) == XED_CATEGORY_CMOV){
        INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)FastForward, IARG_END);
        INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)MOVES_count, IARG_END);
    }
    else if (INS_Category(ins) == XED_CATEGORY_MMX || INS_Category(ins) == XED_CATEGORY_SSE){
        INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)FastForward, IARG_END);
        INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)MMX_SSE_count, IARG_END);
    }
    else if (INS_Category(ins) == XED_CATEGORY_SYSCALL){
        INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)FastForward, IARG_END);
        INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)SYSTEM_CALL_count, IARG_END);
    }
    else if (INS_Category(ins) == XED_CATEGORY_X87_ALU){
        INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)FastForward, IARG_END);
        INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)FP_count, IARG_END);
    }
    else{
        INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)FastForward, IARG_END);
        INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)OTHER_count, IARG_END);
    }
}


VOID Fini(INT32 code, VOID *v)
{    output();

}

int main(int argc, char *argv[])
{
    // Initialize PIN library. Print help message if -h(elp) is specified
    // in the command line or the command line is invalid 
    if( PIN_Init(argc,argv) )
    {
        return Usage();
    }
    
    string fileName = KnobOutputFile.Value();
    fast_forward_count = KnobFastForward.Value();
    if (!fileName.empty()) { 
        out = new std::ofstream(fileName.c_str());
    }
    if (KnobCount)
    {
        INS_AddInstrumentFunction(Instructions, 0);
        // Register function to be called to instrument traces
        TRACE_AddInstrumentFunction(Trace, 0);

        // Register function to be called for every thread before it starts running
        PIN_AddThreadStartFunction(ThreadStart, 0);

        // Register function to be called when the application exits
        PIN_AddFiniFunction(Fini, 0);
    }
    
    cerr <<  "===============================================" << endl;
    cerr <<  "This application is instrumented by MyPinTool" << endl;
    if (!KnobOutputFile.Value().empty()) 
    {
        cerr << "See file " << KnobOutputFile.Value() << " for analysis results" << endl;
    }
    cerr <<  "===============================================" << endl;

    PIN_StartProgram();
    
    return 0;
}