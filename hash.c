/*
 * $Id: hash.c,v 1.9 2002/02/15 19:29:18 erik Exp $
 *
 * hash.h -- generic non-dynamic hash
 *
 * Alexis Yushin, <alexis@nlnetlabs.nl>
 *
 * Copyright (c) 2001, NLnet Labs. All rights reserved.
 *
 * This software is an open source.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * Neither the name of the NLNET LABS nor the names of its contributors may
 * be used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "hash.h"

/*
 * Creates a new hash, intializes and returns a pointer to it.
 *
 * Return NULL if mallocf() fails.
 *
 */
hash_t *
hash_create(mallocf, cmpf, hashf, size)
	void *(*mallocf)(size_t);
	int (*cmpf)(void *, void *);
	unsigned long (*hashf)(void *);
	unsigned long size;
{
	hash_t *hash;


	/* Invalid argument... */
	if(size == 0) {
		errno = EINVAL;
		return NULL;
	}

	/* Allocate memory for it */
	if((hash = mallocf(sizeof(hash_t) + sizeof(hnode_t) * size)) == NULL) {
		return NULL;
	}

	/* Initialize it */
	hash->table = (hnode_t *)(hash + 1);
	hash->size = size;
	bzero(hash->table, sizeof(hnode_t) * hash->size);
	hash->collisions = hash->count = 0;
	hash->mallocf = mallocf;
	hash->cmp = cmpf;
	hash->hash = hashf;

	return hash;
};

/*
 * Inserts a node into a hash.
 *
 * Returns if hash->mallocf() fails or the pointer to the newly added
 * data otherwise.
 *
 * If told to overwrite will replace the duplicate key and data with
 * the new values (thus will NOT destroy the existing node first),
 * otherwise will return the pointer to the data of already existing
 * data.
 *
 */
void *
hash_insert(hash, key, data, overwrite)
	hash_t *hash;
	void *key, *data;
	int overwrite;
{
	hnode_t *node = &hash->table[hash->hash(key) % hash->size];

	if(node->key == NULL) {
		node->key = key;
		node->data = data;
		hash->count++;
		return node;
	} else {
		while(node->next) {
			if(hash->cmp(key, node->key) == 0) {
				if(overwrite) {
					node->next->key = key;
					node->next->data = data;
				} else {
					return NULL;
				}
			}
			node = node->next;
		}

		/* If out of memory, give up... */
		if((node->next = hash->mallocf(sizeof(hnode_t))) == NULL) {
			return NULL;
		}

		hash->count++;
		hash->collisions++;

		bzero(node->next, sizeof(hnode_t));
		node->next->key = key;
		node->next->data = data;
	}
	return node;
}

/*
 * Searches the hash, returns the data if key is found or NULL otherwise.
 *
 */
void *
hash_search(hash, key)
	hash_t *hash;
	void *key;
{
	hnode_t *node = &hash->table[hash->hash(key) % hash->size];

	while(node) {
		if(node->key == NULL) return NULL;
		if(hash->cmp(key, node->key) == 0) {
			return node->data;
		}
		node = node->next;
	}
	return NULL;
}

/*
 * Finds the first element in the hash
 *
 */
hnode_t *
hash_first(hash)
	hash_t *hash;
{
	for(hash->_i = 0; hash->_i < hash->size; hash->_i++) {
		if(hash->table[hash->_i].key != NULL)
			return (hash->_node = &hash->table[hash->_i]);
	}

	return (hash->_node = NULL);
}

/*
 * Returns the next node...
 *
 */
hnode_t *
hash_next(hash)
	hash_t *hash;
{
	if(hash->_node->next) {
		hash->_node = hash->_node->next;
		return hash->_node;
	}

	hash->_i++;

	for(;;) {
		if(hash->_i >= hash->size)
			return NULL;

		if(hash->table[hash->_i].key != NULL)
			return (hash->_node = &hash->table[hash->_i]);

		hash->_i++;
	}
}

/* void hash_delete __P((hash_t *, void *, int, int)); */

void
hash_destroy(hash, freekeys, freedata)
	hash_t *hash;
	int freekeys;
	int freedata;
{
	unsigned i;
	hnode_t *node;

	if(hash == NULL)
		return;

	for(i = 0; i < hash->size; i++) {
		while(hash->table[i].next) {
			node = hash->table[i].next->next;
			if(hash->table[i].next->key && freekeys) free(hash->table[i].next->key);
			if(hash->table[i].next->data && freedata) free(hash->table[i].next->data);
			free(hash->table[i].next);
			hash->table[i].next = node;
		}
		if(hash->table[i].key && freekeys) free(hash->table[i].key);
		if(hash->table[i].data && freedata) free(hash->table[i].data);
	}
	free(hash);
}

#ifdef TEST

unsigned long
hashf(key)
	char *key;
{
        unsigned hash = 0;

        while (*key)
                hash = hash * 31 + *key++;
        return hash;
}


#define	BUFSZ	1000

int
main(argc, argv)
	int argc;
	char **argv;
{
	hash_t *hash;
	char buf[BUFSZ];
	char *key, *data;

	if((hash = hash_create(malloc, strcmp, hashf, 65536)) == NULL) {
		perror("cannot create hash");
		exit(1);
	}

	while(fgets(buf, BUFSZ - 1, stdin)) {
		if(hash_insert(hash, strdup(buf), strdup(buf), 1) == NULL) {
			perror("cannot insert into a hash");
			exit(1);
		}
	}
	fprintf(stderr, "loaded hash table %lu entries, %lu collisions\n", hash->count,
			hash->collisions);
	HASH_WALK(hash, key, data) {
		printf("%s", key);
	}
	hash_destroy(hash, 1, 1);
	return 0;
}
#endif
