#include <stdio.h>
#include <stdint.h>
#include "bitmap.h"
#include "block_store.h"

#include <string.h>
// include more if you need

// You might find this handy.  I put it around unused parameters, but you should
// remove it before you submit. Just allows things to compile initially.
#define UNUSED(x) (void)(x)



typedef struct block_store{
    char* blocks[BLOCK_STORE_NUM_BLOCKS][BLOCK_SIZE_BYTES]; //Blocks 127 made by FM
    bitmap_t* fbm;
} block_store_t;

block_store_t *block_store_create()
{
    block_store_t* block_store_ptr = malloc(sizeof(block_store_t));
    if (block_store_ptr != NULL) {
        bitmap_t *bitmap_ptr = bitmap_create(BLOCK_SIZE_BITS);

        //This is kind of hacky but it works...
        memcpy((block_store_ptr->blocks[127]), bitmap_ptr, sizeof(char)*32);
        bitmap_t* bmp_ptr_new = (bitmap_t*)&block_store_ptr->blocks[127];

        block_store_ptr->fbm = bmp_ptr_new;
        bitmap_set(block_store_ptr->fbm, 127);


        return block_store_ptr;
    } else {
        return NULL;
    }
}

void block_store_destroy(block_store_t *const bs){
    if(bs != NULL && bs->fbm != NULL){
        free(bs);
        return;
    }
}

size_t block_store_allocate(block_store_t *const bs){
    if(bs == NULL) {
        return SIZE_MAX;
    }



    size_t bit_loc = bitmap_ffz(bs->fbm); //find first zero

 
        

        if (bit_loc == SIZE_MAX || bit_loc == BLOCK_STORE_AVAIL_BLOCKS+1) {
            return SIZE_MAX;
        }
        

    if (bit_loc > 126) {
            bitmap_set(bs->fbm, bit_loc); //set first zero

            return bit_loc-1;
    } else {
        bitmap_set(bs->fbm, bit_loc); //set first zero
        return bit_loc;
    }
}

bool block_store_request(block_store_t *const bs, const size_t block_id){
    if(bs == NULL || block_id > BLOCK_STORE_NUM_BLOCKS-1) {
        return 0;
    }

    if(bitmap_test(bs->fbm, block_id) == 1) { 
        return 0; 
    }

    bitmap_set(bs->fbm, block_id);

    //Should never happen unless for some reason our bitmap doesn't work!
    if(bitmap_test(bs->fbm, block_id) == 0)  {
        return 0; 
    }

    return 1;

}
void block_store_release(block_store_t *const bs, const size_t block_id){
    if(bs != NULL) {
        bitmap_reset(bs->fbm, block_id);
    }
}

size_t block_store_get_used_blocks(const block_store_t *const bs){
    if(bs != NULL)
    {
        return bitmap_total_set(bs->fbm)-1; // we are using one for to show the FBM is in use in that slot 
    }

    return SIZE_MAX; 
}

size_t block_store_get_free_blocks(const block_store_t *const bs){
    if(bs != NULL) { 
        return (BLOCK_STORE_NUM_BLOCKS-1)-(bitmap_total_set(bs->fbm)-1); 
    }
    
    return SIZE_MAX; 
}

size_t block_store_get_total_blocks()
{
    return BLOCK_STORE_NUM_BLOCKS-1;
}

size_t block_store_read(const block_store_t *const bs, const size_t block_id, void *buffer){
    if(bs == NULL || block_id > BLOCK_STORE_NUM_BLOCKS-1|| buffer == NULL) {
        return 0 ;
    }

if (block_id >= 127) {
    memcpy(buffer, bs->blocks[block_id+1], BLOCK_STORE_NUM_BLOCKS+1);
    } else {
    memcpy(buffer, bs->blocks[block_id], BLOCK_STORE_NUM_BLOCKS+1);
    }

    return BLOCK_STORE_NUM_BLOCKS;
}


size_t block_store_write(block_store_t *const bs, const size_t block_id, const void *buffer){
    if(bs == NULL || block_id > BLOCK_STORE_NUM_BLOCKS-1|| buffer == NULL) {
        return 0; 
    } if (block_id >= 127) {
        memcpy(bs->blocks[block_id+1], buffer, BLOCK_STORE_NUM_BLOCKS);
    } else {
    memcpy(bs->blocks[block_id], buffer, BLOCK_STORE_NUM_BLOCKS);
    }
    return BLOCK_STORE_NUM_BLOCKS;
}

block_store_t *block_store_deserialize(const char *const filename)
{
    if(filename == NULL || *filename == 0) { 
        return 0; 
    }

    FILE *fd = fopen(filename, "r");
    if (fd == NULL)
    {
        return 0;
    }    


    block_store_t* block_store_ptr = malloc(sizeof(block_store_t));
    bitmap_t *bitmap_ptr = bitmap_create(BLOCK_SIZE_BITS);

    if (block_store_ptr != NULL) {
        //This is kind of hacky but it works...
        memcpy((block_store_ptr->blocks[127]), bitmap_ptr, sizeof(char)*32);
        bitmap_t* bmp_ptr_new = (bitmap_t*)&block_store_ptr->blocks[127];

        block_store_ptr->fbm = bmp_ptr_new;
        char* buff[BLOCK_STORE_NUM_BLOCKS][BLOCK_SIZE_BYTES];
        fread(buff, BLOCK_STORE_NUM_BLOCKS * BLOCK_SIZE_BYTES, 1 , fd );
        memcpy((block_store_ptr->blocks), buff, sizeof(char)*BLOCK_STORE_NUM_BLOCKS*BLOCK_SIZE_BYTES);
    }
    fclose(fd);

    return block_store_ptr;
}

size_t block_store_serialize(const block_store_t *const bs, const char *const filename)
{
    if(bs == NULL || filename == NULL || *filename == 0) { 
        return 0; 
    }

    FILE *fd = fopen(filename, "w");
    if (fd == NULL)
    {
        return 0;
    }

    fwrite(bs->blocks, BLOCK_STORE_NUM_BLOCKS * BLOCK_SIZE_BYTES, 1 , fd );

    fclose(fd);
    return (BLOCK_STORE_NUM_BLOCKS * BLOCK_SIZE_BYTES);

}