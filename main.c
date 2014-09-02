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
					printf("LB(opt:%d, uimm:%d);\n", opt, uimm);
				}
				break;
			case OSECPU_INST_LIMM:
				{
					int imm = fetch_b32value(code, &i, code_bytes);
					int r = fetch_b32value(code, &i, code_bytes);
					int bit = fetch_b32value(code, &i, code_bytes);
					printf("LIMM(bit:%d, r:R%02X, imm:0x%08x);\n", bit, r, imm);
				}
				break;
			case OSECPU_INST_PLIMM:
				{
					int uimm = fetch_b32value(code, &i, code_bytes);
					int p = fetch_b32value(code, &i, code_bytes);
					printf("PLIMM(p:P%02X, uimm:%d);\n", p, uimm);
				}
				break;
			case OSECPU_INST_CND:
				{
					int r = fetch_b32value(code, &i, code_bytes);
					printf("CND(r:R%02X);\n", r);
				}
				break;
			case OSECPU_INST_LMEM:
				{
					int p = fetch_b32value(code, &i, code_bytes);
					int typ = fetch_b32value(code, &i, code_bytes);
					int zero = fetch_b32value(code, &i, code_bytes);
					int r = fetch_b32value(code, &i, code_bytes);
					int bit = fetch_b32value(code, &i, code_bytes);
					printf("LMEM(bit:%d, r:R%02X, typ:%d, p:P%02X, %d);\n", bit, r, typ, p, zero);
				}
				break;
			case OSECPU_INST_SMEM:
				{
					int r = fetch_b32value(code, &i, code_bytes);
					int bit = fetch_b32value(code, &i, code_bytes);
					int p = fetch_b32value(code, &i, code_bytes);
					int typ = fetch_b32value(code, &i, code_bytes);
					int zero = fetch_b32value(code, &i, code_bytes);
					printf("SMEM(bit:%d, r:R%02X, typ:%d, p:P%02X, %d);\n", bit, r, typ, p, zero);
				}
				break;
			case OSECPU_INST_PADD:
				{
					int p1 = fetch_b32value(code, &i, code_bytes);
					int typ = fetch_b32value(code, &i, code_bytes);
					int r = fetch_b32value(code, &i, code_bytes);
					int bit = fetch_b32value(code, &i, code_bytes);
					int p0 = fetch_b32value(code, &i, code_bytes);
					printf("PADD(bit:%d, p0]P%02X, typ:%d, p1:P%02X, r:R%02X);\n", bit, p0, typ, p1, r);
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
						printf("CP(r0:R%02X, r1:R%02X);\n", r0, r1);
					} else {
						printf("%s(bit:%d, r0:R%02X, r1:R%02X, r2:R%02X);\n", operate_inst_name[instid-OSECPU_INST_OR], bit, r0, r1, r2);
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
					printf("%s(bit0:%d, bit1:%d, r0:R%02X, r1:R%02X, r2:R%02X);\n", compare_inst_name[instid-OSECPU_INST_CMPE], bit0, bit1, r0, r1, r2);
				}
				break;
			case OSECPU_INST_PCP:
				{
					int p1 = fetch_b32value(code, &i, code_bytes);
					int p0 = fetch_b32value(code, &i, code_bytes);
					printf("PCP(p0:P%02X, p1:P%02X);\n", p0, p1);
				}
				break;
			case OSECPU_INST_DATA:
				{
					int typ = fetch_b32value(code, &i, code_bytes);
					int len = fetch_b32value(code, &i, code_bytes);
					printf("data(typ:%d, len:%d);\n", typ, len);
					i += len*4;
				}
				break;
			case OSECPU_INST_LIDR:
				{
					int imm = fetch_b32value(code, &i, code_bytes);
					int dr = fetch_b32value(code, &i, code_bytes);
					printf("LIDR(dr:D%02X, imm:%d);\n", dr, imm);
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
					while (skipcnt-- > 0) {
						fetch_b32value(code, &i, code_bytes);
					}
					printf("REM%02X(...);\n", uimm);
				}
				break;
			default:
				printf("(unknown instruction:%x)\n", instid);
				goto fin;
		}
		
		// fetch a next instruction
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

