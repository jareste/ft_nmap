#include <ft_malloc.h>
#include <stdlib.h>
#include <ft_list.h>

list_t* list_get_next(list_t *node)
{
    if (node == NULL) return NULL;
    return node->next;
}

void list_add_last(list_t **head, char *data, char *procedence, input_type type)
{
    if (data == NULL || procedence == NULL) return;
    
    list_t *new_node = malloc(sizeof(list_t));
    new_node->node.data = strdup(data);
    new_node->node.procedence = strdup(procedence);
    new_node->node.type = type;
    new_node->next = NULL;

    if (*head == NULL)
    {
        *head = new_node;
    }
    else
    {
        list_t *current = *head;
        while (current->next != NULL)
        {
            current = current->next;
        }
        current->next = new_node;
    }
}

void list_remove_single(list_t **head, list_t *node_to_remove)
{
    if (*head == NULL || node_to_remove == NULL) return;

    if (*head == node_to_remove)
    {
        list_t *temp = *head;
        *head = (*head)->next;
        free(temp->node.data);
        free(temp);
        return;
    }

    list_t *current = *head;
    while (current->next != NULL && current->next != node_to_remove)
    {
        current = current->next;
    }

    if (current->next == node_to_remove)
    {
        list_t *temp = current->next;
        current->next = temp->next;
        free(temp->node.data);
        free(temp);
    }
}

char* get_data(list_t *node)
{
    return node->node.data;
}

char* get_procedence(list_t *node)
{
    return node->node.procedence;
}

input_type get_type(list_t *node)
{
    return node->node.type;
}

void list_clear(list_t **head)
{
    list_t *current = *head;
    list_t *next_node;

    while (current != NULL)
    {
        next_node = current->next;
        free(current->node.data);
        free(current->node.procedence);
        free(current);
        current = next_node;
    }

    *head = NULL;
}


#include <stdio.h>
void list_print(list_t *head)
{
    list_t *current = head;
    while (current != NULL)
    {
        printf("%s -> ", current->node.data);
        current = current->next;
    }
    printf("NULL\n");
}