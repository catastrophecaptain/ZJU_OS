#ifndef __PRINTK_H__
#define __PRINTK_H__

#include "stddef.h"

#define bool _Bool
#define true 1
#define false 0

#define RED "\033[31m"
#define GREEN "\033[32m"
#define YELLOW "\033[33m"
#define BLUE "\033[34m"
#define PURPLE "\033[35m"
#define DEEPGREEN "\033[36m"
#define CLEAR "\033[0m"


int printk(const char *, ...);
#define Log(format, ...) ;;
#define Err(format, ...) ;;
#endif