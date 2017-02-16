
/*! @file
 *  This is an example of the PIN tool that demonstrates some basic PIN APIs 
 *  and could serve as the starting point for developing your first PIN tool
 */

#include "pin.H"
#include <iostream>
#include <fstream>
#include <set>
#include <vector>

using namespace std;

ofstream OutFile;
/* ================================================================== */
// Global variables 
/* ================================================================== */

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

static UINT64 insArray[500];
static UINT64 Operands[6];
static UINT64 readCount[50];
static UINT64 writeCount[50];
static UINT64 maxInsLength = 0;
static UINT64 maxOpLength = 0;
static UINT64 maxRead = 0;
static UINT64 maxWrite = 0;

static UINT64 memSize[6];
static UINT64 readmemSize[50];
static UINT64 writememSize[50];
static UINT64 maxMem = 0;
static UINT64 maxMemRead = 0;
static UINT64 maxMemWrite = 0;

static ADDRINT maxImmediate = 0;
static ADDRINT minImmediate = 0;

std::ostream * out = &cerr;

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,  "pintool",
    "o", "", "specify file name for MyPinTool output");

KNOB<BOOL>   KnobCount(KNOB_MODE_WRITEONCE,  "pintool",
    "count", "1", "count instructions, basic blocks and threads in the application");


/* ===================================================================== */
// Utilities
/* ===================================================================== */

/*!
 *  Print out help message.
 */
INT32 Usage()
{
    cerr << "This tool prints out the number of dynamically executed " << endl <<
            "instructions, basic blocks and threads in the application." << endl << endl;

    cerr << KNOB_BASE::StringKnobSummary() << endl;

    return -1;
}

/* ===================================================================== */
// Analysis routines
/* ===================================================================== */

/*!
 * Increase counter of the executed basic blocks and instructions.
 * This function is called for every basic block when it is about to be executed.
 * @param[in]   numInstInBbl    number of instructions in the basic block
 * @note use atomic operations for multi-threaded applications
 */
VOID CountBbl(UINT32 numInstInBbl)
{
    bblCount++;
    insCount += numInstInBbl;
}

/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */

/*!
 * Insert call to the CountBbl() analysis routine before every basic block 
 * of the trace.
 * This function is called every time a new trace is encountered.
 * @param[in]   trace    trace to be instrumented
 * @param[in]   v        value specified by the tool in the TRACE_AddInstrumentFunction
 *                       function call
 */
VOID Trace(TRACE trace, VOID *v)
{
    // Visit every basic block in the trace
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        // Insert a call to CountBbl() before every basic bloc, passing the number of instructions
        BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)CountBbl, IARG_UINT32, BBL_NumIns(bbl), IARG_END);
    }
}

/*!
 * Increase counter of threads in the application.
 * This function is called for every thread created by the application when it is
 * about to start running (including the root thread).
 * @param[in]   threadIndex     ID assigned by PIN to the new thread
 * @param[in]   ctxt            initial register state for the new thread
 * @param[in]   flags           thread creation flags (OS specific)
 * @param[in]   v               value specified by the tool in the 
 *                              PIN_AddThreadStartFunction function call
 */
VOID ThreadStart(THREADID threadIndex, CONTEXT *ctxt, INT32 flags, VOID *v)
{
    threadCount++;
}

ADDRINT FastForward(void) {
    return (icount >= fast_forward_count && icount < fast_forward_count + 1000000000);
}

VOID ins_count(){
    icount++;
}

VOID StaticAnalysis(UINT32 insSize, UINT32 opSize, UINT32 readSize, UINT32 writeSize){
    insArray[insSize-1]++;
    if(insSize > maxInsLength) maxInsLength = insSize;
    
    Operands[opSize]++;
    if(opSize > maxOpLength) maxOpLength = opSize;
    
    readCount[readSize]++;
    if(readSize > maxRead) maxRead = readSize;
    
    writeCount[writeSize]++;
    if(writeSize > maxWrite) maxWrite = writeSize;
}

VOID DynamicAnalysis(UINT32 memCount, UINT32 memReadCount, UINT32 memWriteCount){
    memSize[memCount]++;
    if(memCount > maxMem) maxMem = memCount;

    readmemSize[memReadCount]++;
    if(memReadCount > maxMemRead) maxMemWrite = memReadCount;
    
    writememSize[memWriteCount]++;
    if(memWriteCount > maxMemWrite) maxMemWrite = memWriteCount;
}

VOID NOP_count()
{
    nopcount++;
    latency++;
    executed_ins++;
}

VOID DIRECT_CALL_count()
{
    direct_call_count++;
    latency++;
    executed_ins++;
}

VOID INDIRECT_CALL_count()
{
    indirect_call_count++;
    latency++;
    executed_ins++;
}

VOID RETURN_count()
{
    return_count++;
    latency++;
    executed_ins++;
}

VOID UNCONDITIONAL_count()
{
    unconditional_count++;
    latency++;
    executed_ins++;
}

VOID CONDITIONAL_count()
{
    conditional_count++;
    latency++;
    executed_ins++;
}

VOID LOGICAL_count()
{
    logical_count++;
    latency++;
    executed_ins++;
}

VOID ROTATE_SHIFT_count()
{
    rotate_shift_count++;
    latency++;
    executed_ins++;
}

VOID FLAG_CALL_count()
{
    flag_call_count++;
    latency++;
    executed_ins++;
}

VOID VECTOR_count()
{
    vector_count++;
    latency++;
    executed_ins++;
}

VOID MOVES_count()
{
    moves_count++;
    latency++;
    executed_ins++;
}

VOID MMX_SSE_count()
{
    mmx_sse_count++;
    latency++;
    executed_ins++;
}

VOID SYSTEM_CALL_count()
{
    system_call_count++;
    latency++;
    executed_ins++;
}

VOID FP_count()
{
    fp_count++;
    latency++;
    executed_ins++;
}

VOID OTHER_count()
{
    other_count++;
    latency++;
    executed_ins++;
}

VOID RecordMemRead(UINT32 c){
    read_count += c;
    executed_ins += c;
    latency += c*50;
}

VOID RecordMemWrite(UINT32 c){
    write_count += c;
    executed_ins += c;
    latency += c*50;
}

VOID InstructionFootprint(UINT32 addr, UINT32 ins_chunks){
    insAddresses.insert(addr);
    if (ins_chunks == 2) insAddresses.insert(addr+32);
}

VOID DataFootprint(VOID *addr, UINT32 refSize){
    UINT32 dataAddress = *((UINT32*)(&addr));
    UINT32 data_chunks = ((dataAddress)/32)==((dataAddress+refSize)/32)?1:2;
    dataAddresses.insert(dataAddress);
    if(data_chunks == 2) dataAddresses.insert(dataAddress+32);
}

VOID Operand_Size(UINT32 value){
    if(value > maxImmediate) maxImmediate = value;
    else if(value < minImmediate) minImmediate = value;
}

VOID Instructions(INS ins, VOID *v)
{
    UINT32 memReadCount = 0;
    UINT32 memWriteCount = 0;
    UINT32 memOperands = INS_MemoryOperandCount(ins);
    UINT32 opSize = INS_OperandCount(ins);
    UINT32 readSize = INS_MaxNumRRegs(ins);
    UINT32 writeSize = INS_MaxNumWRegs(ins);
    UINT32 insSize = INS_Size(ins);
    UINT32 insAddress = INS_Address(ins);
    UINT32 ins_chunks = (insAddress/32)==((insAddress+insSize)/32)?1:2;
    insAddress = (insAddress/32)*32;
    
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)ins_count, IARG_END);

    UINT32 operandCount = INS_OperandCount(ins);
    for (UINT32 op = 0; op < operandCount; op++){
        if (INS_OperandIsImmediate(ins, op)){
            ADDRINT immediateValue = INS_OperandImmediate(ins, op);
            INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)FastForward, IARG_END);
            INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)Operand_Size, IARG_ADDRINT, immediateValue,  IARG_END);        
        }
    }

    INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)FastForward, IARG_END);
    INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)InstructionFootprint, IARG_UINT32, insAddress, IARG_UINT32, ins_chunks, IARG_END);
    
    INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)FastForward, IARG_END);
    INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)StaticAnalysis, IARG_UINT32, insSize, IARG_UINT32, opSize, IARG_UINT32, readSize, IARG_UINT32, writeSize, IARG_END); 
    
    for (UINT32 memOp = 0; memOp < memOperands; memOp++){
        UINT32 refSize = INS_MemoryOperandSize(ins, memOp);
        UINT32 accesses;
        if (refSize%4 == 0) accesses = refSize/4;
        else accesses = refSize/4+1;
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)DataFootprint, IARG_INST_PTR, IARG_MEMORYOP_EA, memOp, IARG_UINT32, refSize, IARG_END);
        if (INS_MemoryOperandIsRead(ins, memOp)){
            memReadCount++;
            INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)FastForward, IARG_END);
            INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordMemRead, IARG_UINT32, accesses, IARG_END);
        }
        if (INS_MemoryOperandIsRead(ins, memOp)){
            memWriteCount++;
            INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)FastForward, IARG_END);
            INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWrite, IARG_UINT32, accesses, IARG_END);
        }
    }
    INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)FastForward, IARG_END);
    INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)DynamicAnalysis, IARG_UINT32, memOperands, IARG_UINT32, memReadCount, IARG_UINT32, memWriteCount, IARG_END);
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
/*!
 * Print out analysis results.
 * This function is called when the application exits.
 * @param[in]   code            exit code of the application
 * @param[in]   v               value specified by the tool in the 
 *                              PIN_AddFiniFunction function call
 */
VOID Fini(INT32 code, VOID *v)
{
    OutFile.setf(ios::showbase);
    OutFile <<  "===============================================" << endl;
    OutFile <<  "MyPinTool analysis results: " << endl;
    OutFile <<  "Part-A: " << endl;
    OutFile <<  "Number of instructions: " << icount  << endl;
    OutFile <<  "Number of instructions executed: " << executed_ins  << endl;
    OutFile <<  "Number of NOP Instructions: " << nopcount << endl;
    OutFile <<  "Number of Direct Call Instructions: " << direct_call_count << endl;
    OutFile <<  "Number of Indirect Call Instructions: " << indirect_call_count << endl;
    OutFile <<  "Number of Return Call Instructions: " << return_count << endl;
    OutFile <<  "Number of Unconditional Branch Instructions: " << unconditional_count << endl;
    OutFile <<  "Number of Conditional Branch Instructions: " << conditional_count << endl;
    OutFile <<  "Number of Logical Instructions: " << logical_count << endl;
    OutFile <<  "Number of Rotate and Shift Instructions: " << rotate_shift_count << endl;
    OutFile <<  "Number of Flag Instructions: " << flag_call_count << endl;
    OutFile <<  "Number of Vector Instructions: " << vector_count << endl;
    OutFile <<  "Number of Conditional move Instructions: " << moves_count << endl;
    OutFile <<  "Number of MMX and SSE Instructions: " << mmx_sse_count << endl;
    OutFile <<  "Number of System Call Instructions: " << system_call_count << endl;
    OutFile <<  "Number of Floating point Instructions: " << fp_count << endl;
    OutFile <<  "Number of Other Instructions: " << other_count << endl;
    OutFile <<  "Number of Read Operations: " << read_count << endl;
    OutFile <<  "Number of Write Operations: " << write_count << endl;
    OutFile <<  "Total number of Instructions: " << icount << endl;
    OutFile <<  "===============================================" << endl;
    OutFile <<  "Part-B: " << endl;
    OutFile <<  "Number of Cycles executed: " << latency << endl;
    OutFile <<  "CPI: " << (float)latency/icount << endl;
    OutFile <<  "===============================================" << endl;
    OutFile <<  "Part-C: " << endl;
    OutFile <<  "Instruction Footprint: " << insAddresses.size() << endl;
    OutFile <<  "Data Footprint: " << dataAddresses.size() << endl;
    OutFile <<  "Memory Footprint: " << insAddresses.size() + dataAddresses.size() << endl;
    OutFile <<  "===============================================" << endl;
    OutFile <<  "Part-D: " << endl;
    OutFile <<  "Distribution of instruction length 1: " << insArray[0] << endl;
    OutFile <<  "Distribution of instruction length 0: " << Operands[0] << endl;
    OutFile <<  "===============================================" << endl;
    OutFile <<  "Number of basic blocks: " << bblCount  << endl;
    OutFile <<  "Number of threads: " << threadCount  << endl;
    OutFile <<  "===============================================" << endl;
    OutFile.close();
}

/*!
 * The main procedure of the tool.
 * This function is called when the application image is loaded but not yet started.
 * @param[in]   argc            total number of elements in the argv array
 * @param[in]   argv            array of command line arguments, 
 *                              including pin -t <toolname> -- ...
 */
int main(int argc, char *argv[])
{
    // Initialize PIN library. Print help message if -h(elp) is specified
    // in the command line or the command line is invalid 
    if( PIN_Init(argc,argv) )
    {
        return Usage();
    }
    
    string fileName = KnobOutputFile.Value();

    if (!fileName.empty()) { 
        //out = new std::ofstream(fileName.c_str());
        OutFile.open(KnobOutputFile.Value().c_str());
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

    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
