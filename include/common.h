#pragma once

#include<stdio.h>
#include<stdint.h>

#define NL_NEVER 0
#define NL_END  -1

/*!
 * prints buffer in hex format
 * @param buffer [in] any type of buffer with length bytes
 * @param bytes [in] length of buffer
 * @param new_line_freq [in] after printing new_line_freq bytes a newline is inserted
 *
 * new_line_freq can also contain 0 and -1 for no \n and only at end respectively
 */
void print_hex(void* buffer, size_t bytes, ssize_t new_line_freq){

	unsigned char* tmp_buffer = (unsigned char *) buffer;

	for(size_t i = 0; i < bytes; i++){
		printf("%x ", tmp_buffer[i]);
		if(i != 0 && new_line_freq > 0 && i % (new_line_freq - 1) == 0){
			printf("\n");
		}
	}
	if(new_line_freq != 0 && (new_line_freq % (bytes) != 0 || new_line_freq == -1)) printf("\n");
}
/*!
 * @brief prints a non null-terminated string
 * @param string [in] String to print
 * @param len [in] length of string
 */
void print_string(char* string, size_t len){
	for(size_t i = 0; i < len; i++){
		printf("%c", string[i]);
	}
}

static int check_read(size_t read, size_t expected, FILE* file){
	if(read < expected){
		int error = 0;
		if(feof(file) == 0 && (error = ferror(file)) != 0){
			fprintf(stderr, "Error %d occured!\n", error);
			return -1;	
		}
		else if(feof(file) != 0){
			return -2;
		}

	}
	return 0;
}

/*!
 * @brief reads size * nmemb bytes from file
 * @param buffer [out] any type of buffer with length size * nmemb
 * @param size [in] size of one element
 * @param nmemb [in] amount of elements
 * @param file [in] file to read
 * @return 0 on success, -1 on error, -2 on EOF
 */
int read_bytes(void* buffer, size_t size, size_t nmemb, FILE* file){
	const size_t read = fread(buffer, size, nmemb, file);
	return check_read(read*size, nmemb*size, file);
}


/*!
 * @brief converts byte_count bytes from data into a uint64_t number
 * @param data [in] pointer to char buffer containing data
 * @param byte_count [in] amount of bytes to convert into number
 * @return number built from bytes
 * the first byte will be the most significant and the last the least significant byte.
 * data has to store the bytes in big-endianess!
 */
uint64_t convert_bytes_to_number(uint8_t* data, size_t byte_count){
	if(byte_count > sizeof(uint64_t)){
		fprintf(stderr, "[WARNING] byte_count is higher than 8, bytes will be lost due to overflow!\n");
	}

	uint64_t number = 0;
	for(size_t i = 0; i < byte_count; i++){
		number <<= 8;
		number |= *data;
		data++;

	}
	
	return number;
}
