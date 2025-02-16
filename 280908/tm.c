/**
 * @file   tm.c
 * @author [Joseph Vavalà]
 *
 * @section LICENSE
 *
 * [...]
 *
 * @section DESCRIPTION
 *
 * Implementation of your own transaction manager.
 * You can completely rewrite this file (and create more files) as you wish.
 * Only the interface (i.e. exported symbols and semantic) must be preserved.
**/

// Requested features
#define _GNU_SOURCE
#define _POSIX_C_SOURCE   200809L
#ifdef __STDC_NO_ATOMICS__
    #error Current C11 compiler does not support atomic operations
#endif

// External headers
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
// Internal headers
#include <tm.h>

// -------------------------------------------------------------------------- //

/** Define a proposition as likely true.
 * @param prop Proposition
**/
#undef likely
#ifdef __GNUC__
    #define likely(prop) \
        __builtin_expect((prop) ? 1 : 0, 1)
#else
    #define likely(prop) \
        (prop)
#endif

/** Define a proposition as likely false.
 * @param prop Proposition
**/
#undef unlikely
#ifdef __GNUC__
    #define unlikely(prop) \
        __builtin_expect((prop) ? 1 : 0, 0)
#else
    #define unlikely(prop) \
        (prop)
#endif

/** Define one or several attributes.
 * @param type... Attribute names
**/
#undef as
#ifdef __GNUC__
    #define as(type...) \
        __attribute__((type))
#else
    #define as(type...)
    #warning This compiler has no support for GCC attributes
#endif

/* Implementation 
  */
// Constants to define whether tx is read only or write
// static const tx_t read_only_tx  = UINTPTR_MAX - 10;
// static const tx_t read_write_tx = UINTPTR_MAX - 11;

 // Lock -> readwrite_lock (so both shared and exclusive modes)
// check better, perhaps pthread_rwlock is the one you need
struct lock_t {
    pthread_mutex_t mutex;
};
// Lock Operations

static bool lock_init(struct lock_t* lock) {
    return pthread_mutex_init(&(lock->mutex), NULL) == 0;
}

static void lock_cleanup(struct lock_t* lock) {
    pthread_mutex_destroy(&(lock->mutex));
}
// exclusive lock access
static bool lock_acquire(struct lock_t* lock) {
    return pthread_mutex_lock(&(lock->mutex)) == 0;
}

static void lock_release(struct lock_t* lock) {
    pthread_mutex_unlock(&(lock->mutex));
}

size_t get_nb_items(size_t size, size_t align){
    return (size_t)size/align;
}

// get t_var index
size_t get_index(shared_t shared, void const* source as(unused)){
    void * start = tm_start(shared);
    return (source - start) / tm_align(shared);
}

typedef struct{
    unsigned int ts;
    pthread_mutex_t mutex;
    bool lock_flag;
}t_variables;

typedef struct{
    bool readonly;
    void * readset; // array of integers
    void * writeset; // array of integers
    char * local_copy; // array of memory pieces
    void * initial_ts;
    void * timestamps;
}transaction;

struct region {
    void* start;        // Start of the shared memory region
    size_t size;        // Size of the shared memory region (in bytes)
    size_t align;       // Claimed alignment of the shared memory region (in bytes)
    size_t align_alloc; // Actual alignment of the memory allocations (in bytes)
    size_t nb_itemz; // nb of items for easier retrieval
    t_variables * t_var;
};


// -------------------------------------------------------------------------- //

/** Create (i.e. allocate + init) a new shared memory region, with one first non-free-able allocated segment of the requested size and alignment.
 * @param size  Size of the first shared segment of memory to allocate (in bytes), must be a positive multiple of the alignment
 * @param align Alignment (in bytes, must be a power of 2) that the shared memory region must support
 * @return Opaque shared memory region handle, 'invalid_shared' on failure
**/
shared_t tm_create(size_t size as(unused), size_t align as(unused)) {
    struct region* region = (struct region*) malloc(sizeof(struct region)); //allocate memory region 
    if (unlikely(!region)) {
        return invalid_shared;
    }
    size_t align_alloc = align < sizeof(void*) ? sizeof(void*) : align;
    // Allocate first segment of the region
    if (unlikely(posix_memalign(&(region->start), align_alloc, size) != 0)) {
        free(region);
        return invalid_shared;
    }
    
    // initialize the region with zeros
    memset(region->start, 0, size);
    
    // initialize region elements
    region->size        = size;
    region->align       = align;
    region->align_alloc = align_alloc;
    size_t nb_items = size / align;
    region->nb_itemz = nb_items;
    // check here
    t_variables * t_vars = (t_variables *) calloc(nb_items, sizeof(t_variables));
    if (unlikely(!t_vars)) {
        free(region);
        return invalid_shared;
    }
    region->t_var = t_vars;
    // initialize all the locks
    for(size_t i = 0; i < nb_items; i++){
        lock_init(region->t_var[i].mutex);
        region->t_var[i].lock_flag = false;
        region->t_var[i].ts = 0u; // should be zero by defaut but CHECK
    }
    return region;
    
}

/** Destroy (i.e. clean-up + free) a given shared memory region.
 * @param shared Shared memory region to destroy, with no running transaction
**/
void tm_destroy(shared_t shared as(unused)) {
    struct region* region = (struct region*) shared;
    // should check that all locks are free, i.e. no write transaction ongoing 
    
    // and remove all subsequent links + free the memory
    free(region->t_var);
    free(region->start);
    free(region);
}

/** [thread-safe] Return the start address of the first allocated segment in the shared memory region.
 * @param shared Shared memory region to query
 * @return Start address of the first allocated segment
**/
void* tm_start(shared_t shared as(unused)) {
    return ((struct region*) shared)->start;
}

/** [thread-safe] Return the size (in bytes) of the first allocated segment of the shared memory region.
 * @param shared Shared memory region to query
 * @return First allocated segment size
**/
size_t tm_size(shared_t shared as(unused)) {
    return ((struct region*) shared)->size; 
}

/** [thread-safe] Return the alignment (in bytes) of the memory accesses on the given shared memory region.
 * @param shared Shared memory region to query
 * @return Alignment used globally
**/
size_t tm_align(shared_t shared as(unused)) {
    return ((struct region*) shared)->align; ;
}

size_t tm_nb_itemz(shared_t shared as(unused)) {
    return ((struct region*) shared)->itemz; 
}

/** [thread-safe] Begin a new transaction on the given shared memory region.
 * @param shared Shared memory region to start a transaction on
 * @param is_ro  Whether the transaction is read-only
 * @return Opaque transaction ID, 'invalid_tx' on failure
**/
tx_t tm_begin(shared_t shared as(unused), bool is_ro as(unused)) {
    transaction* tx = (transaction*) malloc(sizeof(transaction)); //allocate memory to store transaction's data 
    if (unlikely(!tx)) {
        return invalid_tx;
    }
    tx->readonly = is_ro;
    size_t size = tm_size(shared);
    size_t align = tm_align(shared);
    size_t nb_items = get_nb_items(size, align);
    //size_t nb_items = get_nb_items(size, align);
    
    if(is_ro){
        int * rset = NULL;
        rset = (int *) malloc(nb_items * sizeof(int));
        int * timest = NULL;
        timest = (int *) malloc(nb_items * sizeof(int));
        
        for(size_t i = 0; i< nb_items; i++){
            rset[i] = 0;
            timest[i] = 0;
        }
        tx->readset = rset;
        tx->timestamps = timest;
    }
    else{
        int * wset = NULL;
        wset = (int *) malloc(nb_items * sizeof(int));
        int * rset = NULL;
        rset = (int *) malloc(nb_items * sizeof(int));
        int * timest = NULL;
        timest = (int *) malloc(nb_items * sizeof(int));
        int * init_ts = NULL;
        init_ts = (int *) malloc(nb_items * sizeof(int));
        
        // init array -> x nb_items HERE
        char * init_v = (char*) calloc(nb_items, sizeof(char))
        //(t_variables *) calloc(nb_items, sizeof(t_variables));
        tx.local_copy = NULL; // 
        
        void* source_item = tm_start(shared);
        for(size_t i = 0; i< nb_items; i++){
            if(!shared->t_var[i].lock_flag){
                memcpy(init_v[i], source_item, align);
            }
            else{
                init_v[i] = NULL;
            }
            wset[i] = 0;
            rset[i] = 0;
            timest[i] = 0;
            init_ts[i] = 0;
            source_item = (char*) source_item + align;
        }
        tx->writeset    = wset;
        tx->readset     = rset;
        tx->timestamps  = timest;
        tx->initial_ts  = init_ts;
        tx->local_copy  = init_v;
    }
    return tx;
}

/** [thread-safe] End the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to end
 * @return Whether the whole transaction committed
**/
bool tm_end(shared_t shared as(unused), tx_t tx as(unused)) {
    // replace with shared->nb_itemz HERE
    //size_t size = tm_size(shared);
    size_t align = tm_align(shared);
    size_t nb_items = shared->nb_itemz;
    
    if(tx->readonly){
        // free all R arrays
        free(tx->readset);
        free(tx->timestamps);
        // free transaction
        free(tx);
    }
    else{ // HERE
        
        if(!tm_validate(shared, tx)){ 
            tm_abort();
            return false; 
        }
        void* public_item = tm_start(shared);
        for(size_t i = 0; i < nb_items; i++){
            if(tx->writeset[i]==1){
                shared->t_var[i].ts = tx->timestamps[i] +1;
                memcpy(public_item, tx->local_copy[i], align);
                public_item = (char *) public_item + align;
                free(tx->local_copy[i]); // free each piece of local_copy HERE check whether * needed or should "typecast"
                lock_release(shared->t_var[i].mutex);
                shared->t_var[i].lock_flag = false;
            }
        }
        // free all W arrays
        free(tx->writeset);
        free(tx->readset);
        free(tx->timestamps);
        free(tx->initial_ts);
        // free initial_vals HERE
        free(tx);
    }
    return true;
}

/** [thread-safe] Read operation in the given transaction, source in the shared region and target in a private region.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param source Source start address (in the shared region)
 * @param size   Length to copy (in bytes), must be a positive multiple of the alignment
 * @param target Target start address (in a private region)
 * @return Whether the whole transaction can continue
**/

bool tm_validate(shared_t shared as(unused), tx_t tx as(unused)){
    // get nb_items
    size_t size = tm_size(shared);
    size_t align = tm_align(shared);
    size_t nb_items = size/align;
    // iterate readset
    for(size_t i = 0; i < nb_items; i++){
        if(tx->readset[i]==1){
            if(tx->readonly){
                if(shared->t_var[i].ts != tx->timestamps[i]){
                    return false; // validation failed
                }
            }
            else if((shared->t_var[i].lock_flag == true && tx->writeset[i]==0)){ // if locked and not in this tx wset
                return false;
            }
        }
    }
    return true;
}

bool tm_abort(shared_t shared as(unused), tx_t tx as(unused)){ // the grading tool will not call tm_end if tx aborts, hence either I call it or tm_abort takes care of the rollback & memory freeing.
    if(!tx->readonly){ // if tx performed both w & r
        size_t nb_items = shared->nb_itemz;
        void* public_item = tm_start(shared);
        for(size_t i = 0; i < nb_items; i++){
            if(tx->writeset[i]==1){ // NO need to rollback values and initial timestamps because they were never written
                free(tx->local_copy[i]);
                // release locks
                lock_release(shared->t_var[i].mutex);
                shared->t_var[i].lock_flag = false;
                // restore previous version memcpy(this_align, target in shared, size) HERE
            }
        }
        // free
        // free all W arrays
        free(tx->writeset);
        free(tx->readset);
        free(tx->timestamps);
        free(tx->initial_ts);
        // free initial_vals HERE
        free(tx->local_copy);
        free(tx);
    }
    else{ // "rollback" for read
        // free all R arrays
        free(tx->readset);
        free(tx->timestamps);
        // free transaction
        free(tx);
    }
    return true; // HERE
}

bool tm_read(shared_t shared as(unused), tx_t tx as(unused), void const* source as(unused), size_t size as(unused), void* target as(unused)) {
    // check size validity
    size_t align = tm_align(shared);
    if(size % align != 0){
        return false;
    }
    size_t mem_index = get_index(shared, source);
    size_t nb_items = get_nb_items(size, align);
    
    // first if m belongs to wset
    if(!tx->readonly){ // add if ! tm_validate() -> abort HERE
        for(size_t i = mem_index; i < (nb_items + mem_index); i++){
            if(tx->writeset[i]==0){ // item not in tx write_set
                if(shared->t_var[i].lock_flag == true){
                    // call tm_abort
                    return false;
                }// why break here?
                break;
            }
            if(i == (nb_items + mem_index - 1)){
                memcpy(target, source, size); // HERE at the end
                return true;
            }
    }
        if(!tm_validate()){ // HERE
            tm_abort(); 
            return false;
        }
    for(size_t i = mem_index; i < (nb_items + mem_index); i++){
        if(tx->readset[i]==0){ // item not in tx read_set yet
            tx->readset[i] = 1;
            tx->timestamps[i] = (int) shared->t_var[i].ts; // too much granularity in the timestamps, probably this will cause problems
        }
    }
    memcpy(target, source, size); // HERE
        return true;
    }
    
}

/** [thread-safe] Write operation in the given transaction, source in a private region and target in the shared region.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param source Source start address (in a private region)
 * @param size   Length to copy (in bytes), must be a positive multiple of the alignment
 * @param target Target start address (in the shared region)
 * @return Whether the whole transaction can continue
**/
bool tm_write(shared_t shared as(unused), tx_t tx as(unused), void const* source as(unused), size_t size as(unused), void* target as(unused)) {
    size_t align = tm_align(shared);
    if(size % align != 0){
        return false;
    }
    size_t mem_index = get_index(shared, source);
    size_t nb_items = get_nb_items(size, align);
    
    for(size_t i = mem_index; i < (nb_items + mem_index); i++){
        if(tx->writeset[i]==0){ // item not in tx write_set
            if(lock_acquire(shared->t_var[i].mutex)){
                tx->writeset[i] = 1;
                tx->initial_ts[i] = (int) shared->t_var[i].ts;
                // store in tx->initial_vals[i] only that specific fragment of memory 
            }
            else{
                tm_abort(shared, tx); // HERE
                return false;
            }
        }
    }
    // perhaps need to update the ts for all to the highest found during the iterations
    memcpy(target, source, size);
    return true;
}

/** [thread-safe] Memory allocation in the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param size   Allocation requested size (in bytes), must be a positive multiple of the alignment
 * @param target Pointer in private memory receiving the address of the first byte of the newly allocated, aligned segment
 * @return Whether the whole transaction can continue (success/nomem), or not (abort_alloc)
**/
alloc_t tm_alloc(shared_t shared as(unused), tx_t tx as(unused), size_t size as(unused), void** target as(unused)) {
    // TODO: tm_alloc(shared_t, tx_t, size_t, void**)
    return abort_alloc;
}

/** [thread-safe] Memory freeing in the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param target Address of the first byte of the previously allocated segment to deallocate
 * @return Whether the whole transaction can continue
**/
bool tm_free(shared_t shared as(unused), tx_t tx as(unused), void* target as(unused)) {
    // TODO: tm_free(shared_t, tx_t, void*)
    return false;
}
