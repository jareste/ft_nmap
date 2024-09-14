NAME = ft_nmap

#########
RM = rm -rf
CC = cc
CFLAGS = -Werror -Wextra -Wall
LDFLAGS = -lm
RELEASE_CFLAGS = $(CFLAGS) -DNDEBUG
#########

#########
FILES = main md5 ft_malloc parse_arg sha256 ft_list utils whirlpool blake2s base64

SRC = $(addsuffix .c, $(FILES))

vpath %.c srcs srcs/md5 inc srcs/parse_arg srcs/sha256 srcs/utils srcs/whirlpool srcs/blake2s srcs/base64
#########

#########
OBJ_DIR = objs
OBJ = $(addprefix $(OBJ_DIR)/, $(SRC:.c=.o))
DEP = $(addsuffix .d, $(basename $(OBJ)))
#########

#########
$(OBJ_DIR)/%.o: %.c
	@mkdir -p $(@D)
	${CC} -MMD $(CFLAGS) -c -Isrcs/md5 -Iinc -Isrcs/parse_arg -Isrcs/sha256 -Isrcs/utils -Isrcs/whirlpool -Isrcs/blake2s -Isrcs/base64 $< -o $@

all: 
	$(MAKE) $(NAME)

$(NAME): $(OBJ) Makefile
	$(CC) $(CFLAGS) $(OBJ) -o $(NAME) $(LDFLAGS)
	@echo "EVERYTHING DONE  "
	@./.add_path.sh

release: CFLAGS = $(RELEASE_CFLAGS)
release: re
	@echo "RELEASE BUILD DONE  "

clean:
	$(RM) $(OBJ) $(DEP)
	$(RM) -r $(OBJ_DIR)
	@echo "OBJECTS REMOVED   "

fclean: clean
	$(RM) $(NAME)
	@echo "EVERYTHING REMOVED   "

re:	fclean all

.PHONY: all clean fclean re release

-include $(DEP)
