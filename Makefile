NAME = ft_nmap

#########
RM = rm -rf
CC = cc
CFLAGS = -Werror -Wextra -Wall
LDFLAGS = -lm
RELEASE_CFLAGS = $(CFLAGS) -DNDEBUG
#########

#########
FILES = main ft_malloc parse_arg ft_list nmap 

SRC = $(addsuffix .c, $(FILES))

vpath %.c srcs inc srcs/parse_arg srcs/nmap 
#########

#########
OBJ_DIR = objs
OBJ = $(addprefix $(OBJ_DIR)/, $(SRC:.c=.o))
DEP = $(addsuffix .d, $(basename $(OBJ)))
#########

#########
$(OBJ_DIR)/%.o: %.c
	@mkdir -p $(@D)
	${CC} -MMD $(CFLAGS) -c -Isrcs/nmap -Iinc -Isrcs/parse_arg -Isrcs/nmap $< -o $@

all: 
	$(MAKE) $(NAME)

$(NAME): $(OBJ) Makefile
	$(CC) $(CFLAGS) $(OBJ) -o $(NAME) $(LDFLAGS)
	@echo "EVERYTHING DONE  "
#	@./.add_path.sh

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
