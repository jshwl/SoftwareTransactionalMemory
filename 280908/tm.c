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
#include <stdio.h>
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

static bool lock_init(pthread_mutex_t * lock) {
    return pthread_mutex_init((lock), NULL) == 0;
}

static void lock_cleanup(pthread_mutex_t * lock) {
    pthread_mutex_destroy(lock);
}
// exclusive lock access
static bool lock_acquire(pthread_mutex_t* lock) {
    return pthread_mutex_trylock(lock) == 0;
}

static void lock_release(pthread_mutex_t * lock) {
    pthread_mutex_unlock(lock);
}

size_t get_nb_items(size_t size, size_t align){
    return (size_t)size/align;
}

// get t_var index
size_t get_index(shared_t shared, void const* source as(unused)){
    void const * src_addr = source;
    void * start = tm_start(shared);
    size_t align = tm_align(shared);
    size_t diff = source -start;
    size_t index = diff/align;
    printf("get_index \t diff %lu\n", diff);
    printf("get_index \t source %p\n", src_addr);
    printf("get_index \t index \t %lu\n", index);
    return index;
}

typedef struct{
    atomic_uint ts; // atomic unsigned
    pthread_mutex_t mutex;
    bool lock_flag;
}t_variables;

typedef struct{
    bool readonly;
    int * readset; // array of integers   // perhaps pointer to pointers of ints 
    int * writeset; // array of integers  // before void * rset; // int wset[] because only one flexible array is allowed
    char * local_copy; // array of memory pieces
    //atomic_uint * timestamps;
    int * timestamps;
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
    // Allocate first segment of the region // QUESTION HERE
    if (unlikely(posix_memalign(&(region->start), align_alloc, size) != 0)) {
        free(region);
        return invalid_shared;
    }
    
    // initialize the region with zeros
    memset(region->start, 0, size);
   
    //
    printf("tm_create \t start \t %p \n", region->start);
    // initialize region elements
    region->size        = size;
    region->align       = align;
    region->align_alloc = align_alloc;
    size_t nb_items = size / align;
    region->nb_itemz = nb_items;
    
    t_variables * t_vars = (t_variables *) calloc(nb_items, sizeof(t_variables));
    if (unlikely(!t_vars)) {
        free(region);
        return invalid_shared;
    }
    // initialize all the locks
    for(size_t i = 0; i < nb_items; i++){
        lock_init(&t_vars[i].mutex);
        t_vars[i].lock_flag = false; 
        atomic_init(&t_vars[i].ts,0u);
    }
	region->t_var = t_vars;
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

/** [thread-safe] Return the start address of the first allocated segment in the shared memory region. something
 * @param shared Shared memory region to query
 * @return Start address of the first allocated segment
**/
void* tm_start(shared_t shared as(unused)) {
    void * star = ((struct region *)shared)->start;
    printf("tm_start \t start \t %p\n", star);
    return star;
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
    return ((struct region*) shared)->nb_itemz; 
}

/** [thread-safe] Begin a new transaction on the given shared memory region.
 * @param shared Shared memory region to start a transaction on
 * @param is_ro  Whether the transaction is read-only
 * @return Opaque transaction ID, 'invalid_tx' on failure
**/

bool tm_validate(shared_t shared as(unused), tx_t tx as(unused)){
    // txn->readonly shouldn't get here
	struct region * share = (struct region *) shared;
    transaction * txn = (transaction *) tx;
    size_t size = tm_size(shared);
    size_t align = tm_align(shared);
    size_t nb_items = size/align;
    // iterate readset
    for(size_t i = 0; i < nb_items; i++){
        if(txn->readset[i]==1){ // this part requires an atomic order_acquire
            atomic_thread_fence(memory_order_acquire);
            if(share->t_var[i].ts != txn->timestamps[i]){ // careful, comparing atomic_uint and int
                return false; // validation failed
            }// atomic_thread_fence(memory_order_acquire)
            atomic_thread_fence(memory_order_release); // verify that writeset[i] != NULL
            if(share->t_var[i].lock_flag == true && txn->writeset[i]==0){ // if locked and not in this tx wset
                return false;
            }
        }
    }
    return true;
}


bool tm_abort(shared_t shared as(unused), tx_t tx as(unused)){ // the grading tool will not call tm_end if tx aborts, hence either I call it or tm_abort takes care of the rollback & memory freeing.
	transaction * txn = (transaction *) tx;
	struct region * share = (struct region *) shared;
    if(!txn->readonly){ // if tx performed both w & r
        size_t nb_items = tm_nb_itemz(shared);
        void* public_item = tm_start(shared);
        for(size_t i = 0; i < nb_items; i++){
            if(txn->writeset[i]==1){ // NO need to rollback values and initial timestamps because they were never written
                lock_release(&share->t_var[i].mutex);
                share->t_var[i].lock_flag = false;
                // do I need an atomic operation and specify memory_order_release?
            }
        }
        free(txn->writeset);
        free(txn->readset);
        free(txn->timestamps);
        free(txn->local_copy);
        free(txn);
    }
    else{
        free(txn);
    }
    return true;
}

tx_t tm_begin(shared_t shared as(unused), bool is_ro as(unused)) {
// try to fix "request for member in something not a structure or union"
	struct region * share = (struct region *) shared;
	size_t size = tm_size(shared);
    size_t align = tm_align(shared);
	size_t nb_items = tm_nb_itemz(share);
    //transaction* tx = (transaction*) malloc(sizeof(transaction)); // careful, things could be in positions other than you think. + nb_items * sizeof(int));
	transaction* tx = (transaction*) malloc(sizeof(transaction));
    if (unlikely(!tx)) {
        return invalid_tx;
    }
    tx->readonly = is_ro;
    
    if(is_ro){ // try to return immediately when this calls read -> so just return true and in tm_read if(txn->readonly) memcpy()...
        return tx;
    }
    else{
        int * wset = NULL;
        wset = (int *) malloc(nb_items * sizeof(int));
        if (unlikely(!wset)) {
        	return invalid_tx;
    	}
        
        int * rset = NULL;
        rset = (int *) malloc(nb_items * sizeof(int));
        if (unlikely(!rset)) {
      	  return invalid_tx;
  		}
  		
        /* // atomic version on transactions too
        (atomic_uint *) timest = (atomic *) calloc(nb_items, sizeof(atomic_uint)); // or malloc, with calloc all init to 0
        if (unlikely(!timest) {
        	return invalid_tx;
    	}
    	*/
        int * timest = NULL;
        timest = (int *) malloc(nb_items * sizeof(int));
        if (unlikely(!timest)) {
        	return invalid_tx;
   		}
   		
        char * init_v = (char*) calloc(nb_items * align, sizeof(char)); //  posix_memalign
        //char * init_v = (char*) malloc(nb_items * sizeof(char));
        if (unlikely(!init_v)){
        	return invalid_tx;
    	}
        
        void* source_item = tm_start(shared);
        for(size_t i = 0; i< nb_items; i++){
            timest[i] = atomic_load_explicit(&share->t_var[i].ts, memory_order_acquire); // perhaps no need at this point, can be done at tm_write time
            wset[i] = 0;
            rset[i] = 0;
            source_item = (char*) source_item + align;
        }
        tx->writeset    = wset;
        tx->readset     = rset;
        tx->timestamps  = timest;
        tx->local_copy  = init_v; // not initialized, could set all entries to null
    }
    return tx;
}

/** [thread-safe] End the given transaction.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to end
 * @return Whether the whole transaction committed
**/
bool tm_end(shared_t shared as(unused), tx_t tx as(unused)) {
	struct region * share = (struct region *) shared;
	transaction * txn = (transaction *) tx;
    // replace with shared->nb_itemz HERE
    //size_t size = tm_size(shared);
    size_t align = tm_align(shared);
    size_t nb_items = tm_nb_itemz(shared);
    
    if(txn->readonly){
        free(txn);
    }
    else{ // HERE
        bool res = tm_validate(shared, tx);
        if(!res){
            tm_abort(shared, tx);
            return false; 
        }
        void* public_item = tm_start(shared);
        for(size_t i = 0; i < nb_items; i++){ // copy piece by piece in shared memory + update the timestamp atomically
            if(txn->writeset[i] == 1){
                //atomic_fetch_add_explicit(&share->t_var[i].ts,1, memory_order_release);
                atomic_store_explicit(&share->t_var[i].ts, txn->timestamps[i] +1, memory_order_release); // better way to do t_var[i].ts = atomic_F&A(txn->timestamps[i])?
                memcpy(public_item, &txn->local_copy[i*align], align);
                public_item = (char *) public_item + align;
                lock_release(&share->t_var[i].mutex);
                share->t_var[i].lock_flag = false;
            }
        }
		free(txn->local_copy);
        free(txn->writeset);
        free(txn->readset);
        free(txn->timestamps);
        free(txn);
    }
    return true;
}



bool tm_read(shared_t shared as(unused), tx_t tx as(unused), void const* source as(unused), size_t size as(unused), void* target as(unused)) {
	struct region * share = (struct region *) shared;
	transaction * txn = (transaction *) tx;
    // check size validity
    size_t align = tm_align(shared);
    if(size % align != 0){ // if assumption holds align should be == size for reads
        return false;
    }
    if(txn->readonly){
        memcpy(target, source, size); // under assumption from TA
        return true;
    }
    printf("tm_read src_addr \t %p\n", source);
    size_t mem_index = get_index(share, source);
    size_t nb_items = get_nb_items(size, align);
    
    // first if m belongs to wset

    for(size_t i = mem_index; i < (nb_items + mem_index); i++){  // reading from where the process asks
        if(txn->writeset[i]==0){ // item not in tx write_set
            if(share->t_var[i].lock_flag == true){
               tm_abort(share, txn);
               return false;
            }
            break;
        }
        if(i == (nb_items + mem_index - 1)){ // finished loop without encountering a non-wset element-> hence can read immediately -> wrong! I must read my own local_copy with the updates!
            //memcpy(target, source, size); // if you have previously modified them then there's no need to "re-read" AKA copy them on themselves
            // wrong! just do memcpy()   // PAYLOAD INSTEAD OF ADDRESS!
            memcpy(target, &txn->local_copy[mem_index*align], size);
            //try 
            return true;
        }
    }
	bool res = tm_validate(share, txn);
    if(!res){ // HERE
        tm_abort(share, txn); 
        return false;
    }
    for(size_t i = mem_index; i < (nb_items + mem_index); i++){
        if(txn->readset[i]==0){ // item not in tx read_set yet // here correct finding the highest timestamp instead and updating it for every piece of memory?
            txn->readset[i] = 1;
            txn->timestamps[i] = atomic_load_explicit(&share->t_var[i].ts, memory_order_acquire);
            //txn->timestamps[i] = (int) share->t_var[i].ts; // too much granularity in the timestamps, probably this will cause problems
        }
    }
    memcpy(target, source, size); // or in local copy?
    memcpy(&txn->local_copy[mem_index*align], source, size); // try both HERE * ALIGN or NOT
    return true;
}

/** [thread-safe] Write operation in the given transaction, source in a private region and target in the shared region.
 * @param shared Shared memory region associated with the transaction
 * @param tx     Transaction to use
 * @param source Source start address (in a private region)
 * @param size   Length to copy (in bytes), must be a positive multiple of the alignment
 * @param target Target start address (in the shared region)
 * @return Whether the whole transaction can continue
**/
bool tm_write(shared_t shared as(unused), tx_t tx as(unused), void const* source as(unused), size_t size as(unused), void* target as(unused)) { // target is what we need for--
	struct region * share = (struct region *) shared;
	transaction * txn = (transaction *) tx;
    size_t align = tm_align(shared);
    if(size % align != 0){
        return false;
    }
    printf("tm_write \t source %p \n", target);
    size_t mem_index = get_index(share, target);
    printf("tm_write \t index \t %lu\n", mem_index);
    size_t nb_items = get_nb_items(size, align);
    
    printf("tm_write \t nb_items \t %lu\n", nb_items);
    
    void* public_item = tm_start(shared);
    for(size_t i = mem_index; i < (nb_items + mem_index); i++){ // HERE copy from "source"[i] to local_copy[i]
            if(txn->writeset[i]==0){ // item not in tx write_set
                if(lock_acquire(&share->t_var[i].mutex)){ // try to add it, plus get the timestamp in an atomic way
                    txn->timestamps[i] = atomic_load_explicit(&share->t_var[i].ts, memory_order_acquire);
                    txn->writeset[i] = 1;
                    memcpy(&txn->local_copy[i*align], public_item, align);
                }
                else{
                    tm_abort(shared, tx); // HERE
                    return false;
                }
            }
            else if(txn->writeset[i]==1){
                memcpy(&txn->local_copy[i*align], public_item, align); // if TX already holds the lock then just write the small fragment in its local_copy
            }
        //update public_item
        public_item = (char *) public_item + align; // update position "+1"
    }
    // perhaps need to update the ts for all to the highest found during the iterations
    //memcpy(&txn->local_copy[mem_index*align], source, size); // need to be sure that local_copy in memory has distance from one item to the other == align
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
