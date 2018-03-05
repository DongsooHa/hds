# coding=UTF-8

import sys, argparse, os

from elf_decoder.ELF     import ELF
from symbolizer.Relation import Relation
from disassembler.Disasm import Disasm
from analysis.DFA        import DFA
from analysis.BSS        import BSS

'''
---------------------------------------------------------------------------------------------------
                                Galaxy S8+ Nougat 64bit library 
                                     (총 584 중 64개가 불완전함)
---------------------------------------------------------------------------------------------------

<특이한 섹션 구조>

    libBargeInEngine.so     libSamsungAPVoiceEngine.so

<일부 함수를 못 찾음>

    libterrier.so           libbauthtzcommon.so     libMMCodec.so       libsavsvc.so
    libIrisTlc.so           libarac.so              libhwui.so          libatomcore.so
    libicui18n.so           libpac.so               libart.so           libfilterpack_facedetect.so

<많은 함수를 못 찾음>

    libdk_native.so         libete.so                libsavscmn.so      libimage_lls.so
    libRSCpuRef.so          libsecsqlite.so          libsmat.so         libsthmb.so
    libsmata.so

<eh_frame의 personality function이 존재함. 많은 함수를 못 찾음>

    libtlc_direct_comm.so   lib_stressanalyzer_v03_jni.so       libsaiv_HprFace_GAE_api.so
    libsaiv_HprFace_api.so  libsaiv_HprFace_cmh_support_jni.so  libsaiv_HprFace_GAE_jni.so
    libsmartfocusengine.so  libHpr_RecGAE_cvFeature_v1.0.so     libHpr_TaskFaceClustering_hierarchical_v1.0.so
    libWineDetection.so     libc_malloc_debug.so                libBestPhoto.so 
    libSSVILibs.so          libblurdetection.so                 libtlc_proxy_comm.so
    libjackshm.so           libsurfaceflinger.so                libHpr_RecFace_dl_v1.0.so
    libIrisService.so       libDualShotMattingCoreLIB.so        libSRIBSE_Lib.so
    libSSOCRLibs.so         libc++.so                           libdmcSmartDP.so
    libdng_sdk.so           libscore.so                         libSensorNativeProtocol.so
    libdmcSmartUX.so        libsaiv_BeautySolution.so           libsaiv_imagesequencestabilizer.so
    libHprVisualEffect.so   libfocuspeaking.so                  libObjectAndSceneClassification_2.0_Lite_Native.so
    libISXBIEngine.so       libpdfium.so                        libObjectAndSceneClassification_2.5_OD.so
    libsec-ims.so           libskia.so                          libsaiv_barcode.so
    libQmageDecoder.so      libhifistill.so
'''

def reassemble(path):
    # Decoding ELF & Initializing object
    rel_info    = Relation()
    elf_info    = ELF(path, rel_info)
    disasm_info = Disasm(elf_info)
    dfa_info    = DFA(disasm_info)
    bss_info    = BSS(disasm_info.get_inst_map(),disasm_info.get_block_map())

    # Collecting function addresses exported
    addr_list_to_disasm = disasm_info.collect_called_addr()
    data_pointer_list   = set()
    code_pointer_list   = set()

    # Disassembling instruction section
    while len(addr_list_to_disasm) != 0 or \
          len(disasm_info.get_pending_list()) != 0 or \
          len(disasm_info.get_pending_sw_list()) != 0:

        while len(addr_list_to_disasm) != 0:
            # STEP 1. Disassembling start addresses of basic block
            new_bk_addrs = disasm_info.disassemble(addr_list_to_disasm)
            addr_list_to_disasm = set()

            # STEP 2. Performing data-flow analysis for collecting relative addresses
            dfa_info.dfa_for_relative_addr(new_bk_addrs)

            # STEP 3. Calculating jump table which is detected previous step 
            #         (for example, switch statement in C)
            for sw_type, sw_jmp_i in disasm_info.get_pending_sw_list():
                # STEP 3-1. Performing backward slicing
                sliced_insts = bss_info.bss_for_switch(sw_jmp_i)
                # STEP 3-2. Finding table base address, table offset count, and target addresses
                new_bk_addrs = disasm_info.find_switch_table(dfa_info.get_state_map(),sliced_insts,sw_type)
                # STEP 3-3. Registering target address found
                addr_list_to_disasm = addr_list_to_disasm.union(new_bk_addrs)
            disasm_info.clear_pending_sw_list()

        # TODO: STEP 4. Calculating address of other indirect control flow
        for _ in disasm_info.get_pending_list():
            pass
        disasm_info.clear_pending_list()

        # STEP 5. Examining that the calculated address points to the code area
        #         Examining that the address in NOTYPE symbol points to the code area
        found_new_bk   = False
        ptr_set_in_sym = disasm_info.get_notype_pointer()
        ptr_set_calc   = dfa_info.get_address_calculted()

        for ptr in ptr_set_calc.union(ptr_set_in_sym):
            if ptr in data_pointer_list or ptr in code_pointer_list:
                continue

            # In order to examine it, we just try to disassemble at the address
            # We consider that the address points to code if disassembling is finish without error
            is_data_ptr, new_bk_addrs = disasm_info.try_to_disassemble(ptr)

            if is_data_ptr:
                data_pointer_list.add(ptr)
            else:
                code_pointer_list.add(ptr)
                dfa_info.dfa_for_relative_addr(new_bk_addrs)
                found_new_bk = True

        # When code pointer is found, we should check whether the blocks include code pointer
        if found_new_bk:
            continue

    # STEP 6. Checking coverage of code section 
    disasm_info.check_code_section_coverage()

    '''
    bk = disasm_info.get_block_map()[0x8D408]
    print(bk.print_dot_included_related_bk(disasm_info.get_block_map(),True))

    # 각 레이어 생성
    il = InstructionLayer(disasm)
    bl = BlockLayer(disasm, il)
    fl = FunctionLayer(disasm, bl)

    # 데이터 흐름 분석
    handler = ELF_Handler(il,bl,fl)
    handler.dfa_for_data_link()
    handler.verification()

    # 난독화 과정
    dex_path    = "./sample/classes.dex"
    rel_info    = RelInfo(handler)
    injector    = Injector(handler,rel_info)
    manipulator = Manipulator(handler,rel_info,injector)

    # 삽입 및 파일 쓰기 과정
    if manipulator.obfuscation(dex_path):
        injector.make_file(args.output_file)
    else:
        raise Exception("Failure of the insertion")
    '''


if __name__ == '__main__':

    # Checking python version
    if sys.version_info[0] < 3:
        print('Python version 3 is required.')
        sys.exit(-1)

    # Parsing argumnets
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--input-file', dest='input_file', type=str)
    parser.add_argument('-d', '--input-dir',  dest='input_dir',  type=str)
    parser.add_argument('-o', '--output',     dest='output',     type=str)
    args = parser.parse_args()

    # Verifying argumnets
    if (len(sys.argv) == 1 or args.output == None) or \
       (args.input_file != None and args.input_dir != None) or \
       (args.input_file == args.input_dir == None):
        parser.print_help()
        sys.exit(-1)

    # Reassembling target ELF file
    if args.input_file != None:
        reassemble(args.input_file)
    else:
        for file_name in os.listdir(args.input_dir):
            print('File: ' + file_name)
            file_path = os.path.join(args.input_dir,file_name)
            reassemble(file_path)
