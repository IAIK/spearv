require_rv64;
//WRITE_RD(MMU.get_tagging()->load_tag(RS1 + insn.i_imm(), (mtag_access) 0));
throw trap_illegal_instruction(0);
