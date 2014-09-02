#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "osecpu.h"

#define B32_SIGNATURE "\x05\xe2\x00\xcf\xee\x7f\xf1\x88"

unsigned char* load_code(const char* filename, long* read_bytes)
{
	FILE* fp;
	long filesize;
	char* code;

	fp = fopen(filename, "rb");
	if (!fp) return NULL;

	fseek(fp, 0, SEEK_END);
	filesize = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	code = malloc(filesize);
	if (!code) {
		fclose(fp);
		return NULL;
	}

	fread(code, filesize, 1, fp);

	fclose(fp);

	if (strncmp(code, B32_SIGNATURE, 8) != 0) {
		free(code);
		return NULL;
	}

	*read_bytes = filesize;
	return code;
}

int fetch_b32value(const unsigned char* code, int* pos, int code_bytes)
{
	int i;
	int offset;
	int fetch_bytes;
	int ret_value;

	if (*pos < 0) return 0;

	if (code[*pos] == 0x76) {
		offset = 1;
		fetch_bytes = 3;
	} else if (strncmp(code+*pos, "\xff\xff\xf7\x88", 4) == 0) {
		offset = 4;
		fetch_bytes = 4;
	} else {
		*pos = -1;
		return 0;
	}

	ret_value = 0;
	for (i = 0; i < fetch_bytes; i++) {
		ret_value = (ret_value << 8) | code[*pos+offset+i];
	}

	*pos += offset+fetch_bytes;
	return ret_value;
}

void reverse_aska(const unsigned char* code, int code_bytes)
{
	int i = 0;
	int instpos = 0;
	enum OsecpuInstructionId instid;
	static const char* operate_inst_name[] = {
		"OR", "XOR", "AND", "SBX",
		"ADD", "SUB", "MUL",
		"SHL", "SAR", "DIV", "MOD",
	};
	static const char* compare_inst_name[] = {
		"CMPE", "CMPNE", "CMPL", "CMPGE",
		"CMPLE", "CMPG", "TSTZ", "TSTNZ",
	};

	// fetch a first instruction
	instid = fetch_b32value(code, &i, code_bytes);
	while (i >= 0) {
		switch (instid) {
			case OSECPU_INST_LB:
				{
					int uimm = fetch_b32value(code, &i, code_bytes);
					int opt = fetch_b32value(code, &i, code_bytes);
					printf("%08x(%8d) : %08x          LB(opt:%d, uimm:%d);\n", instpos, instpos, instid, opt, uimm);
					printf("%18c : %08x [uimm]\n", ' ', uimm);
					printf("%18c : %08x [opt]\n", ' ', opt);
				}
				break;
			case OSECPU_INST_LIMM:
				{
					int imm = fetch_b32value(code, &i, code_bytes);
					int r = fetch_b32value(code, &i, code_bytes);
					int bit = fetch_b32value(code, &i, code_bytes);
					printf("%08x(%8d) : %08x          LIMM(bit:%d, r:R%02X, imm:0x%08x);\n", instpos, instpos, instid, bit, r, imm);
					printf("%18c : %08x [imm]\n", ' ', imm);
					printf("%18c : %08x [r]\n", ' ', r);
					printf("%18c : %08x [bit]\n", ' ', bit);
				}
				break;
			case OSECPU_INST_PLIMM:
				{
					int uimm = fetch_b32value(code, &i, code_bytes);
					int p = fetch_b32value(code, &i, code_bytes);
					printf("%08x(%8d) : %08x          PLIMM(p:P%02X, uimm:%d);\n", instpos, instpos, instid, p, uimm);
					printf("%18c : %08x [uimm]\n", ' ', uimm);
					printf("%18c : %08x [p]\n", ' ', p);
				}
				break;
			case OSECPU_INST_CND:
				{
					int r = fetch_b32value(code, &i, code_bytes);
					printf("%08x(%8d) : %08x          CND(r:R%02X);\n", instpos, instpos, instid, r);
					printf("%18c : %08x [r]\n", ' ', r);
				}
				break;
			case OSECPU_INST_LMEM:
				{
					int p = fetch_b32value(code, &i, code_bytes);
					int typ = fetch_b32value(code, &i, code_bytes);
					int zero = fetch_b32value(code, &i, code_bytes);
					int r = fetch_b32value(code, &i, code_bytes);
					int bit = fetch_b32value(code, &i, code_bytes);
					printf("%08x(%8d) : %08x          LMEM(bit:%d, r:R%02X, typ:%d, p:P%02X, %d);\n", instpos, instpos, instid, bit, r, typ, p, zero);
					printf("%18c : %08x [p]\n", ' ', p);
					printf("%18c : %08x [typ]\n", ' ', typ);
					printf("%18c : %08x\n", ' ', zero);
					printf("%18c : %08x [r]\n", ' ', r);
					printf("%18c : %08x [bit]\n", ' ', bit);
				}
				break;
			case OSECPU_INST_SMEM:
				{
					int r = fetch_b32value(code, &i, code_bytes);
					int bit = fetch_b32value(code, &i, code_bytes);
					int p = fetch_b32value(code, &i, code_bytes);
					int typ = fetch_b32value(code, &i, code_bytes);
					int zero = fetch_b32value(code, &i, code_bytes);
					printf("%08x(%8d) : %08x          SMEM(bit:%d, r:R%02X, typ:%d, p:P%02X, %d);\n", instpos, instpos, instid, bit, r, typ, p, zero);
					printf("%18c : %08x [r]\n", ' ', r);
					printf("%18c : %08x [bit]\n", ' ', bit);
					printf("%18c : %08x [p]\n", ' ', p);
					printf("%18c : %08x [typ]\n", ' ', typ);
					printf("%18c : %08x\n", ' ', zero);
				}
				break;
			case OSECPU_INST_PADD:
				{
					int p1 = fetch_b32value(code, &i, code_bytes);
					int typ = fetch_b32value(code, &i, code_bytes);
					int r = fetch_b32value(code, &i, code_bytes);
					int bit = fetch_b32value(code, &i, code_bytes);
					int p0 = fetch_b32value(code, &i, code_bytes);
					printf("%08x(%8d) : %08x          PADD(bit:%d, p0]P%02X, typ:%d, p1:P%02X, r:R%02X);\n", instpos, instpos, instid, bit, p0, typ, p1, r);
					printf("%18c : %08x [p1]\n", ' ', p1);
					printf("%18c : %08x [typ]\n", ' ', typ);
					printf("%18c : %08x [r]\n", ' ', r);
					printf("%18c : %08x [bit]\n", ' ', bit);
					printf("%18c : %08x [p0]\n", ' ', p0);
				}
				break;
			case OSECPU_INST_OR:
			case OSECPU_INST_XOR:
			case OSECPU_INST_AND:
			case OSECPU_INST_SBX:
			case OSECPU_INST_ADD:
			case OSECPU_INST_SUB:
			case OSECPU_INST_MUL:
			case OSECPU_INST_SHL:
			case OSECPU_INST_SAR:
			case OSECPU_INST_DIV:
			case OSECPU_INST_MOD:
				{
					int r1 = fetch_b32value(code, &i, code_bytes);
					int r2 = fetch_b32value(code, &i, code_bytes);
					int r0 = fetch_b32value(code, &i, code_bytes);
					int bit = fetch_b32value(code, &i, code_bytes);
					if (instid == OSECPU_INST_OR && r1 == r2) {
						printf("%08x(%8d) : %08x          CP(r0:R%02X, r1:R%02X);\n", instpos, instpos, instid, r0, r1);
						printf("%18c : %08x [r0]\n", ' ', r0);
						printf("%18c : %08x [r1]\n", ' ', r1);
					} else {
						printf("%08x(%8d) : %08x          %s(bit:%d, r0:R%02X, r1:R%02X, r2:R%02X);\n", instpos, instpos, instid, operate_inst_name[instid-OSECPU_INST_OR], bit, r0, r1, r2);
						printf("%18c : %08x [bit]\n", ' ', bit);
						printf("%18c : %08x [r0]\n", ' ', r0);
						printf("%18c : %08x [r1]\n", ' ', r1);
						printf("%18c : %08x [r2]\n", ' ', r2);
					}
				}
				break;
			case OSECPU_INST_CMPE:
			case OSECPU_INST_CMPNE:
			case OSECPU_INST_CMPL:
			case OSECPU_INST_CMPGE:
			case OSECPU_INST_CMPLE:
			case OSECPU_INST_CMPG:
			case OSECPU_INST_TSTZ:
			case OSECPU_INST_TSTNZ:
				{
					int r1 = fetch_b32value(code, &i, code_bytes);
					int r2 = fetch_b32value(code, &i, code_bytes);
					int bit1 = fetch_b32value(code, &i, code_bytes);
					int r0 = fetch_b32value(code, &i, code_bytes);
					int bit0 = fetch_b32value(code, &i, code_bytes);
					printf("%08x(%8d) : %08x          %s(bit0:%d, bit1:%d, r0:R%02X, r1:R%02X, r2:R%02X);\n", instpos, instpos, instid, compare_inst_name[instid-OSECPU_INST_CMPE], bit0, bit1, r0, r1, r2);
					printf("%18c : %08x [r1]\n", ' ', r1);
					printf("%18c : %08x [r2]\n", ' ', r2);
					printf("%18c : %08x [bit1]\n", ' ', bit1);
					printf("%18c : %08x [r0]\n", ' ', r0);
					printf("%18c : %08x [bit0]\n", ' ', bit0);
				}
				break;
			case OSECPU_INST_PCP:
				{
					int p1 = fetch_b32value(code, &i, code_bytes);
					int p0 = fetch_b32value(code, &i, code_bytes);
					printf("%08x(%8d) : %08x          PCP(p0:P%02X, p1:P%02X);\n", instpos, instpos, instid, p0, p1);
					printf("%18c : %08x [p1]\n", ' ', p1);
					printf("%18c : %08x [p0]\n", ' ', p0);
				}
				break;
			case OSECPU_INST_DATA:
				{
					int typ = fetch_b32value(code, &i, code_bytes);
					int len = fetch_b32value(code, &i, code_bytes);
					int j;
					printf("%08x(%8d) : %08x          data(typ:%d, len:%d);\n", instpos, instpos, instid, typ, len);
					printf("%18c : %08x [typ]\n", ' ', typ);
					printf("%18c : %08x [len]\n", ' ', len);
					printf("%18c : (%d bytes suppressed)\n", ' ', len*4);
					i += len*4;
				}
				break;
			case OSECPU_INST_LIDR:
				{
					int imm = fetch_b32value(code, &i, code_bytes);
					int dr = fetch_b32value(code, &i, code_bytes);
					printf("%08x(%8d) : %08x          LIDR(dr:D%02X, imm:%d);\n", instpos, instpos, instid, dr, imm);
					printf("%18c : %08x [imm]\n", ' ', imm);
					printf("%18c : %08x [dr]\n", ' ', dr);
				}
				break;
			case OSECPU_INST_REM:
				{
					int uimm = fetch_b32value(code, &i, code_bytes);
					int skipcnt = 0;
					switch (uimm)
					{
						case 0x00: skipcnt = 1; break;
						case 0x01: skipcnt = 1; break;
						case 0x02: skipcnt = 2; break;
						case 0x03: skipcnt = 1; break;
						case 0x34: skipcnt = 1; break;
						default:
							printf("(unknown instruction:REM%02X)\n", uimm);
							goto fin;
					}
					printf("%08x(%8d) : %08x          REM%02X(...);\n", instpos, instpos, instid, uimm);
					printf("%18c : %08x\n", ' ', uimm);
					while (skipcnt-- > 0) {
						int value = fetch_b32value(code, &i, code_bytes);
						printf("%18c : %08x\n", ' ', value);
					}
				}
				break;
			default:
				printf("(unknown instruction:%x)\n", instid);
				goto fin;
		}

		// fetch a next instruction
		instpos = i;
		instid = fetch_b32value(code, &i, code_bytes);
	}
fin:
	return;
}

int main(int argc, char** argv)
{
	unsigned char* code;
	long code_bytes;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s app.b32\n", argv[0]);
		exit(EXIT_SUCCESS);
	}

	code = load_code(argv[1], &code_bytes);
	if (!code) {
		fprintf(stderr, "Error (load_code)\n");
		exit(EXIT_FAILURE);
	}

	reverse_aska(code+8, code_bytes-8);

	free(code);

	return 0;
}

