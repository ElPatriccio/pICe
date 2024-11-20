#include<stdlib.h>
#include<stdio.h>
#include<string.h>
#include<stdint.h>
#include<stdbool.h>
#include<stdarg.h>
#include<assert.h>

#include "../include/common.h"

#define ANCILLARY_BIT   0x10000000
#define PRIVATE_BIT     0x00100000
#define RESERVED_BIT    0x00001000
#define SAFE_TO_CPY_BIT 0x00000010

static uint32_t chunk_type_number(char *chunk_name_str);

#define chunk_cmp(chunk_ptr, string) (chunk_ptr->type == chunk_type_number(string))


struct ProgArgs{
	char *filename;
	bool color;
	bool v_flag;
};

struct ChunkData{
	uint32_t len;
	uint32_t type;
	uint8_t *data;
	uint32_t crc;
	struct ChunkData *next;
};

struct IHDRData{
	uint32_t width;
	uint32_t height;
	uint8_t bit_depth;
	uint8_t color_type;
	uint8_t compression;
	uint8_t filter;
	uint8_t interlace;
};

struct ChunkVerify{
	struct ChunkData *first;
	bool present;
	bool multiple;
	bool consecutive;
	bool ordering;	
};

enum PNG_ERROR{
	PNG_NO_ERROR = 0,
	PNG_SYS_FAIL,
	PNG_NOT_PNG,
	PNG_CORRUPTED,
	PNG_EOF,
};

enum ChunkType{
	CT_UNKNOWN = -1,
	CT_IHDR = 0,
	CT_PLTE,
	CT_IDAT,
	CT_IEND,
	CT_cHRM,
	CT_gAMA,
	CT_iCCP,
	CT_sBIT,
	CT_sRGB,
	CT_bKGD,
	CT_hIST,
	CT_tRNS,
	CT_pHYs,
	CT_sPLT,
	CT_tIME,
	CT_iTXt,
	CT_tEXt,
	CT_zTXt,
	CT_COUNT,
};

static_assert(CT_COUNT == 18, "Amount of standard chunks has changed");

char *prog_name = NULL;
struct ProgArgs args;

static void print_usage(void){
	printf("Usage: %s [OPTIONS...] FILE\n", prog_name);
	printf("%s verifies compliance of FILE with the PNG standard v1.2\n", prog_name);
	printf("Options:\n");
	printf("  -c, --disable-color\tdisables colored output\n");
	printf("  -v, --view-chunks\tprint each chunk with corresponding type, length and CRC without error checking\n");
	printf("      --help\t\tdisplay this help and exit\n");
	printf("      --version\t\toutput version information and exit\n");
}

static void parse_args(int argc, char **argv){
	prog_name = argv[0];
	if(argc < 2){
		print_usage();
		exit(EXIT_FAILURE);
	}
	args.color = true;
	args.v_flag = false;

	for(int i = 1; i < argc; i++){
		if(strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--disable-color") == 0){
			args.color = false;
		}
		else if(strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--view-chunks") == 0){
			args.v_flag = true;
		}
		else if(strcmp(argv[i], "--help") == 0){
			print_usage();
			exit(EXIT_SUCCESS);
		}
		else if(strcmp(argv[i], "--version") == 0){
			printf("%s 0.1\n", prog_name);
			printf("Copyright (c) 2024 ElPatriccio\n");
			printf("License MIT: <https://github.com/ElPatriccio/pICe/blob/main/LICENSE>\n");
			exit(EXIT_SUCCESS);
		}
		else if(i == argc - 1){
			args.filename = argv[i];
		}
		else{
			fprintf(stderr, "[ERROR] %s: Unknown option %s\n", prog_name, argv[i]);
			print_usage();
			exit(EXIT_FAILURE);
		}
	}
}

static void print_error(char *fmt, ...){
	va_list va;
	va_start(va, fmt);
	fprintf(stderr, "[");
	
	if(args.color) fprintf(stderr, "\e[31m");

	fprintf(stderr, "ERROR");

	if(args.color) fprintf(stderr, "\e[0m");

	fprintf(stderr, "] ");
	vfprintf(stderr, fmt, va);
	fprintf(stderr, ": ");
	perror("");
	fprintf(stderr, "\n");
	va_end(va);
}

static void print_warning(char *fmt, ...){
	va_list va;
	va_start(va, fmt);
	fprintf(stderr, "[");
	
	if(args.color) fprintf(stderr, "\e[33m");
	
	fprintf(stderr, "WARNING");
	
	if(args.color) fprintf(stderr, "\e[0m");
	
	fprintf(stderr, "] ");
	vfprintf(stderr, fmt, va);
	fprintf(stderr, "\n");
	va_end(va);

}
static void print_info(char *fmt, ...){
	va_list va;
	va_start(va, fmt);
	
	fprintf(stdout, "[");
	
	if(args.color) fprintf(stdout, "\e[34m");
	
	fprintf(stdout, "INFO");
	
	if(args.color) fprintf(stdout, "\e[0m");
	
	fprintf(stdout, "] ");
	vfprintf(stdout, fmt, va);
	fprintf(stdout, "\n");
	va_end(va);
}

static void print_warning(char *fmt, ...);

static bool has_png_header(FILE *image){
	uint8_t png[] = {137, 80, 78, 71, 13, 10, 26, 10};
	uint8_t bytes[8];

	if(read_bytes(bytes, sizeof(uint8_t), 8, image) != 0){
		return 0;
	}
	
	return memcmp(bytes, png, 8) == 0;
}

static uint32_t chunk_type_number(char *chunk_name_str){
	if(chunk_name_str == NULL) return 0;
	return (uint32_t) convert_bytes_to_number((uint8_t*)chunk_name_str, 4);
}

static enum ChunkType chunk_to_enum(const struct ChunkData chunk){
	uint32_t type = chunk.type;

	if(type == chunk_type_number("IHDR")){
		return CT_IHDR;
	}
	if(type == chunk_type_number("PLTE")){
		return CT_PLTE;
	}
	if(type == chunk_type_number("IDAT")){
		return CT_IDAT;
	}
	if(type == chunk_type_number("IEND")){
		return CT_IEND;
	}
	if(type == chunk_type_number("cHRM")){
		return CT_cHRM;
	}
	if(type == chunk_type_number("gAMA")){
		return CT_gAMA;
	}
	if(type == chunk_type_number("iCCP")){
		return CT_iCCP;
	}
	if(type == chunk_type_number("sBIT")){
		return CT_sBIT;
	}
	if(type == chunk_type_number("sRGB")){
		return CT_sRGB;
	}
	if(type == chunk_type_number("bKGD")){
		return CT_bKGD;
	}
	if(type == chunk_type_number("hIST")){
		return CT_hIST;
	}
	if(type == chunk_type_number("tRNS")){
		return CT_tRNS;
	}
	if(type == chunk_type_number("pHYs")){
		return CT_pHYs;
	}
	if(type == chunk_type_number("sPLT")){
		return CT_sPLT;
	}
	if(type == chunk_type_number("tIME")){
		return CT_tIME;
	}
	if(type == chunk_type_number("iTXt")){
		return CT_iTXt;
	}
	if(type == chunk_type_number("tEXt")){
		return CT_tEXt;
	}
	if(type == chunk_type_number("zTXt")){
		return CT_zTXt;
	}

	return CT_UNKNOWN;
}	
static void get_IHDR_data(const struct ChunkData *ihdr_chunk, struct IHDRData *ihdr){
	
	assert(ihdr_chunk->type == chunk_type_number("IHDR"));

	uint8_t *data = ihdr_chunk->data;

	ihdr->width       = (uint32_t) convert_bytes_to_number(data, sizeof(uint32_t));
	data += sizeof(uint32_t);

	ihdr->height      = (uint32_t) convert_bytes_to_number(data, sizeof(uint32_t));
	data += sizeof(uint32_t);

	ihdr->bit_depth   = (uint8_t)  convert_bytes_to_number(data, sizeof(uint8_t));
	data += sizeof(uint8_t);

	ihdr->color_type  = (uint8_t)  convert_bytes_to_number(data, sizeof(uint8_t));
	data += sizeof(uint8_t);

	ihdr->compression = (uint8_t)  convert_bytes_to_number(data, sizeof(uint8_t));
	data += sizeof(uint8_t);

	ihdr->filter      = (uint8_t)  convert_bytes_to_number(data, sizeof(uint8_t));
	data += sizeof(uint8_t);

	ihdr->interlace   = (uint8_t)  convert_bytes_to_number(data, sizeof(uint8_t));
}

static void print_tabs(size_t tabs){
	for(size_t i = 0; i < tabs; i++){
		printf("\t");
	}
}

static size_t print_check(const char *msg, bool success, size_t tab_level){

	print_tabs(tab_level);
	
	if(success){
		if(args.color) printf("\e[1;32m");
		printf("(+)");
		if(args.color) printf("\e[0m");
		printf(" ");
	}
	else{
		if(args.color) printf("\e[1;31m");
		printf("(-)");
		if(args.color) printf("\e[0m");
		printf(" ");
	}
	printf("%s\n", msg);
	
	return success ? 0 : 1;
}

static void print_chunk_type(uint32_t type){
	for(int i = 0; i < 4; i++){
		printf("%c", (char)((type >> (8 * (3-i))) & 0xFF));
	}
}

static void print_chunk_data(const struct ChunkData *chunk){
	printf("Data:\n");
	if(chunk->type ==  chunk_type_number("IHDR")){
		struct IHDRData ihdr = {0};
		get_IHDR_data(chunk, &ihdr);

		printf("\twidth: %u\n", ihdr.width);
		printf("\theight: %u\n", ihdr.height);
		printf("\tbit-depth: %hhu\n", ihdr.bit_depth);
		printf("\tcolor-type: %hhu\n", ihdr.color_type);
		printf("\tcompression: %hhu\n", ihdr.compression);
		printf("\tfilter: %hhu\n", ihdr.filter);
		printf("\tinterlace: %hhu\n", ihdr.interlace);
	}
}

static void print_chunk(const struct ChunkData *chunk){
	printf("Type: ");
	print_chunk_type(chunk->type);
	printf("\n");
	printf("Data len: %u\n", chunk->len);
	printf("CRC: %u\n", chunk->crc);

	if(chunk->len > 0){
		print_chunk_data(chunk);
	}
	printf("\n");
}

static enum PNG_ERROR next_chunk(FILE *image, struct ChunkData **chunk){
	
	int status = 0;
	uint8_t bytes[4];

	if((status = read_bytes(bytes, sizeof(uint8_t), 4, image)) != 0){
		return status == -1 ? PNG_SYS_FAIL : PNG_EOF;
	}
	
	if(*chunk == NULL){
		*chunk = malloc(sizeof(struct ChunkData));
	}
	else if((*chunk)->next == NULL){
		(*chunk)->next = malloc(sizeof(struct ChunkData));
		*chunk = (*chunk)->next;
	}
	
	if(*chunk == NULL){
		print_error("Failed to alloc memory!");
		return PNG_SYS_FAIL;
	}

	(*chunk)->len = (uint32_t) convert_bytes_to_number(bytes, sizeof(uint32_t));

	if((status = read_bytes(bytes, sizeof(uint8_t), 4, image)) != 0){
		free(*chunk);
		*chunk = NULL;
		return status == -1 ? PNG_SYS_FAIL : PNG_CORRUPTED;
	}
	
	(*chunk)->type = (uint32_t) convert_bytes_to_number(bytes, sizeof(uint32_t));

	(*chunk)->data = (uint8_t*) calloc((*chunk)->len, sizeof(uint8_t));
	if((*chunk)->data == NULL){
		free(*chunk);
		*chunk = NULL;
		print_error("Failed to alloc memory!");
		return PNG_SYS_FAIL;
	}
	if((status = read_bytes((*chunk)->data, sizeof(uint8_t), (*chunk)->len, image) != 0)){
		free(*chunk);
		*chunk = NULL;
		return status == -1 ? PNG_SYS_FAIL : PNG_CORRUPTED;
	}	

	if((status = read_bytes(bytes, sizeof(uint8_t), 4, image)) != 0){
		free(*chunk);
		*chunk = NULL;
		return status == -1 ? PNG_SYS_FAIL : PNG_CORRUPTED;
	}

	(*chunk)->crc = (uint32_t) convert_bytes_to_number(bytes, sizeof(uint32_t)); 

	return PNG_NO_ERROR;
}

static enum PNG_ERROR build_chunk_list(FILE *image, struct ChunkData **first_chunk){
	
	struct ChunkData *last_chunk = NULL; 

	enum PNG_ERROR status = PNG_NO_ERROR;
	if((status = next_chunk(image, &last_chunk)) != PNG_NO_ERROR){
		if(status == PNG_EOF){
			return PNG_CORRUPTED;
		}
		else{
			return status;
		}
	}
	*first_chunk = last_chunk;

	while(status == PNG_NO_ERROR){
		status = next_chunk(image, &last_chunk);
	}
	
	return status == PNG_EOF ? PNG_NO_ERROR : status;
}


static size_t verify_IHDR(const struct ChunkData *chunk, struct IHDRData ihdr){
	size_t errors = 0;
		
	assert(chunk->type == chunk_type_number("IHDR"));

	errors += print_check("Length of IHDR data == 13", chunk->len == 13, 1);

	bool bit_depth_valid = ihdr.bit_depth == 1 || ihdr.bit_depth == 2 || ihdr.bit_depth == 4 || ihdr.bit_depth == 8 || ihdr.bit_depth == 16;

	errors += print_check("Bit depth is one of the following: 1, 2, 4, 8, 16", bit_depth_valid, 1);
	
	bool color_type_valid = ihdr.color_type < 7 && (ihdr.color_type % 2 == 0 || ihdr.color_type == 3);
	errors += print_check("Color type is one of the following: 0, 2, 3, 4, 6", color_type_valid, 1);

	bool color_and_bit_valid = bit_depth_valid && color_type_valid && (
			(ihdr.color_type == 0)			       ||
			(ihdr.color_type == 2 && ihdr.bit_depth >= 8)  ||
			(ihdr.color_type == 3 && ihdr.bit_depth != 16) ||
			(ihdr.color_type > 3 && ihdr.bit_depth >= 8)
	     );

	errors += print_check("Color type and bit depth match", color_and_bit_valid, 1);

	errors += print_check("Compression method is set to 0", ihdr.compression == 0, 1); 
	print_check("Filter method is set to 0", ihdr.filter == 0, 1);

	errors += print_check("Interlace method is either 0 or 1", ihdr.interlace < 2, 1);


	return errors;
}

static size_t verify_amount(struct ChunkData *iter, struct ChunkVerify *cv){
	enum ChunkType chunk = chunk_to_enum(*iter);
	switch(chunk){
		case CT_IHDR:
		case CT_PLTE:
		case CT_IEND:
		case CT_cHRM:
		case CT_gAMA:
		case CT_iCCP:
		case CT_sBIT:
		case CT_sRGB:
		case CT_bKGD:
		case CT_hIST:
		case CT_tRNS:
		case CT_pHYs:
		case CT_tIME:
			if(cv[chunk].multiple){
				printf("\tAt most 1 ");
				print_chunk_type(iter->type);
				printf(" is allowed!\n");
				return 1;
			}
			break;
		case CT_IDAT:
			if(!cv[chunk].consecutive){
				printf("\t");
				print_chunk_type(iter->type);
				printf("s must be consecutive!\n");
				return 1;
			}
			break;
		case CT_sPLT:
		case CT_iTXt:
		case CT_tEXt:
		case CT_zTXt:
		case CT_UNKNOWN:
			break;
		case CT_COUNT:
		default:
			print_error("Unreachable");
			assert(false);
	}
	return 0;
}

static size_t verify_ordering(struct ChunkData *iter, struct ChunkVerify *cv, bool *is_present){
	enum ChunkType chunk = chunk_to_enum(*iter);
	switch(chunk){
		case CT_sPLT:
		case CT_pHYs:
		case CT_PLTE:
			if(cv[CT_IDAT].present){
				print_check("This chunk appears before the first IDAT chunk", false, 1);
				return 1;
			}
			break;
		case CT_cHRM:
		case CT_gAMA:
		case CT_iCCP:
		case CT_sBIT:
		case CT_sRGB:
			if(cv[CT_PLTE].present || cv[CT_IDAT].present){
				print_check("This chunk appears before the first PLTE and IDAT chunk", false, 1);
				return 1;
			}
			break;
		case CT_bKGD:
		case CT_hIST:
		case CT_tRNS:
			if(is_present[CT_PLTE] && !cv[CT_PLTE].present){
				print_check("This chunk appears after the PLTE chunk", false, 1);
				return 1;
			}
			if(cv[CT_IDAT].present){
				print_check("This chunk appears before the first IDAT chunk", false, 1);
				return 1;
			}
			break;
		
		case CT_tIME:
		case CT_iTXt:
		case CT_tEXt:
		case CT_zTXt:
		case CT_IHDR:
		case CT_IDAT:
		case CT_IEND:
		case CT_UNKNOWN:
			break;
		case CT_COUNT:
		default:
			print_error("Unreachable");
			assert(false);
	}
	return 0;
}

static size_t verify_chunks(struct ChunkData *chunk_list){

	assert(chunk_list != NULL);

	size_t errors = 0;

	struct ChunkData *iter = chunk_list;
	
	bool chunk_is_present[CT_COUNT] = {0};
	
	while(iter->next != NULL){
		enum ChunkType chunk = chunk_to_enum(*iter);
		if(chunk != CT_UNKNOWN){
			chunk_is_present[chunk] = true;
		}
		iter = iter->next;
	}

	iter = chunk_list;

	struct ChunkVerify cv[CT_COUNT] = {0};
	for(size_t i = 0; i < CT_COUNT; i++){
		cv[i].consecutive = true;
	}
	print_check("First chunk has to be of type IHDR!", chunk_cmp(iter, "IHDR"), 0);
	if(!chunk_cmp(iter, "IHDR")){
		print_warning("Critical chunk IHDR is missing! Further checks can't be done reliably!");
		errors++;
	}
	
	enum ChunkType chunk = chunk_to_enum(*iter);
	cv[chunk].present = true;

	struct IHDRData ihdr = {0};
	if(cv[CT_IHDR].present){
		print_chunk_type(iter->type);
		printf("\n");
		cv[chunk].present = true;
		cv[chunk].first = iter;
		get_IHDR_data(iter, &ihdr);
		errors += verify_IHDR(iter, ihdr);
	}
	struct ChunkData *last = iter;
	iter = iter->next;
	while(iter->next != NULL){
		print_chunk_type(iter->type);
		printf("\n");
		
		chunk = chunk_to_enum(*iter);

		if(chunk != CT_UNKNOWN){
			if(!cv[chunk].present){
				cv[chunk].present = true;
			}
			else{
				cv[chunk].multiple = true;
				cv[chunk].consecutive = last->type == iter->type;
			}
			errors += verify_amount(iter, cv);
			errors += verify_ordering(iter, cv, chunk_is_present);
		}

		last = iter;
		iter = iter->next;
	}
	
	print_chunk_type(iter->type);
	printf("\n");
	chunk = chunk_to_enum(*iter);
	if(chunk != CT_UNKNOWN){
		if(!cv[chunk].present){
			cv[chunk].present = true;
		}
		else{
			cv[chunk].multiple = true;
			cv[chunk].consecutive = last->type == iter->type;
		}
		errors += verify_amount(iter, cv);
		errors += verify_ordering(iter, cv, chunk_is_present);
	}
	print_check("Last chunk is IEND", chunk_cmp(iter, "IEND"), 0);
	if(!chunk_cmp(iter, "IEND")){ 
		errors++;
	}

	return errors;
}

#define return_defer(code) do \
{\
	retstat = code; \
	goto defer; \
}\
while(0)

int main(int argc, char **argv){
	parse_args(argc, argv);
	
	print_info("Reading file %s", args.filename);
	FILE *image = fopen(args.filename, "rb");

	if(image == NULL){
		print_error("Couldn't open file");
		return EXIT_FAILURE;
	}
	
	if(!has_png_header(image)){
		print_info("PNG header is missing! The file %s is not a png image (or was corrupted).", args.filename);
		fclose(image);
		return EXIT_SUCCESS;
	}	

	int retstat = EXIT_SUCCESS;
	enum PNG_ERROR err = PNG_NO_ERROR;
	
	struct ChunkData *chunk_list = NULL;
	if((err = build_chunk_list(image, &chunk_list)) == PNG_SYS_FAIL){
		return_defer(EXIT_FAILURE);
	}

	long image_size = 0;	
	if(fseek(image, 0, SEEK_END) == -1){
		print_error("Failed to seek to end of image");
		return_defer(EXIT_FAILURE);
	}

	if((image_size = ftell(image)) == -1){
		print_error("Failed to get image size");
		return_defer(EXIT_FAILURE);
	}
	
	printf("----------------------------------\n");
	printf("   pICe - PNG Integrity Checker\n");
	printf("----------------------------------\n");
	printf("File size: %ld bytes\n", image_size);
	printf("Chunks:\n\n");
	
	if(args.v_flag){
		struct ChunkData *iter = chunk_list;
		while(iter != NULL){
			print_chunk(iter);
			iter = iter->next;
		}
		return_defer(EXIT_SUCCESS);
	}
	

	size_t errors = verify_chunks(chunk_list);
	
	if(errors > 0){
		print_info("The file %s has %u error(s)!", args.filename, errors);
	}
	else{
		print_info("The file %s complies with the PNG standard (v1.2)", args.filename);
		print_info("0 errors");
	}
defer:	
	// Cleanup
	fclose(image);
	image = NULL;
	struct ChunkData *tmp;
	while(chunk_list != NULL){
		free(chunk_list->data);
		tmp = chunk_list;
		chunk_list = chunk_list->next;
		free(tmp);
	}
	return retstat;
}
