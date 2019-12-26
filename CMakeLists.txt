cmake_minimum_required(VERSION 3.15)
project(OS_8test C)

set(CMAKE_C_STANDARD 99)

add_executable(AES main.c AES.c Decrypt_mode.c Encrypt_mode.c bit_operation.c)