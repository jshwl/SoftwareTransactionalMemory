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

 /*
struct lock_t {
    pthread_mutex_t mutex;
};
*/
struct lock_t {
    pthread_mutex_t mutex;
};

// Lock Operations

static bool lock_init(pthread_mutex_t * lock) {
    return pthread_mutex_init((lock), NULL) == 0;
}

/*
static void lock_cleanup(pthread_mutex_t * lock) {
    pthread_mutex_destroy(lock);
}
*/
// exclusive lock access
static bool lock_acquire(pthread_mutex_t* lock) {
    return pthread_mutex_trylock(lock) == 0;
}

static bool lock_release(pthread_mutex_t * lock) {
    return pthread_mutex_unlock(lock) == 0;
}
// original lock_release
/*
static void lock_release(pthread_mutex_t * lock) {
    pthread_mutex_unlock(lock);
}

*/

size_t get_nb_items(size_t size, size_t align){
    return (size_t)size/align;
}

// USE ATOMIC_FLAG INSTEAD OF LOCK
// 
size_t get_index(shared_t shared, void const* source as(unused)){
    size_t align = tm_align(shared);
    void * start = tm_start(shared);
    size_t index = (source - start) / align;
    return index;
}

void setOne(int * val){
    *val = 1;
    return;
}
void setZero(int * val){
    *val = 0;
    return;
}
void setFalse(bool * flag){
    *flag = false;
    return;
}
void setTrue(bool * flag){
    *flag = true;
    return;
}

void setTS(int * ts, int sharedTS){
    *ts = sharedTS;
    return;
}
void setTSg2l(int * localTS, atomic_uint ts){
    *localTS = (int) ts;
    return;
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
    //printf("---------------tm_create \t start \t %p --------------\n", region->start);
    // initialize region elements
    region->size        = size;
    region->align       = align;
    region->align_alloc = align_alloc;
    size_t nb_items = size / align;
    
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
	printf("-------------------- created region + items = %lu ------------------\n", nb_items);
    return region;
    
}

/** Destroy (i.e. clean-up + free) a given shared memory region.
 * @param shared Shared memory region to destroy, with no running transaction
**/
void tm_destroy(shared_t shared as(unused)) {
   //printf("-------------------- destroyed region ------------------\n");
    struct region* share = (struct region*) shared;
    free(share->t_var);
    free(share->start);
    free(share);
}

void* tm_start(shared_t shared as(unused)) {
    void * star = ((struct region *)shared)->start;
    return star;
}

size_t tm_size(shared_t shared as(unused)) {
    return ((struct region*) shared)->size; 
}

size_t tm_align(shared_t shared as(unused)) {
    return ((struct region*) shared)->align; ;
}


bool tm_validateRO(shared_t shared as(unused), tx_t tx as(unused), size_t nb_items){
	struct region * share = (struct region *) shared;
    transaction * txn = (transaction *) tx;
	for(size_t i = 0; i < nb_items; i++){
        if(txn->readset[i]==1){ 
            if((int)share->t_var[i].ts != txn->timestamps[i] || share->t_var[i].lock_flag == true){
                return false;
            }
        }
        
    }
    return true;
}

bool tm_validate(shared_t shared as(unused), tx_t tx as(unused), size_t nb_items){
	struct region * share = (struct region *) shared;
    transaction * txn = (transaction *) tx;
    // iterate readset
    for(size_t i = 0; i < nb_items; i++){
        if(txn->readset[i]==1){ // this part requires an atomic order_acquire   perhaps                   //atomic_thread_fence(memory_order_acquire);
            if((int)share->t_var[i].ts != txn->timestamps[i]){ // careful, comparing atomic_uint and int
                return false; // validation failed
            }// atomic_thread_fence(memory_order_acquire)
            if(share->t_var[i].lock_flag == true && txn->writeset[i]!=1){ // if locked and not in this tx wset
                return false;
            }   
        }
    }
    return true;
}


bool tm_abort(shared_t shared as(unused), tx_t tx as(unused)){ 
	transaction * txn = (transaction *) tx;
	struct region * share = (struct region *) shared;
	size_t size = tm_size(shared);
    size_t align = tm_align(shared);
	size_t nb_items = size / align;
    if(!txn->readonly){ // if tx performed both w & r
        //printf("<tm_abort> end WR\n");
       //printf("WR aborting %lu\n", nb_items);
        for(size_t i = 0; i < nb_items; i++){
            if(txn->writeset[i]==1){ // NO NEED TO REWRITE, just free the memory txn->local_copy and release the lock HERE add Fence or atomic TestAndSet
                lock_release(&share->t_var[i].mutex);
                setFalse(&share->t_var[i].lock_flag);
            }
        }
        free(txn->writeset);
        free(txn->readset);
        free(txn->timestamps);
        free(txn->local_copy);
        free(txn);
    }
    else{
        free(txn->readset);
        free(txn->timestamps);
        free(txn);
    }
    return true;
}
// I'm intersted in the timestamps only when I start reading // otherwise things will always be different from the initial state and all txs will fail
tx_t tm_begin(shared_t shared as(unused), bool is_ro as(unused)) {
	struct region * share = (struct region *) shared;
	size_t size = tm_size(shared);
    size_t align = tm_align(shared);
	size_t nb_items = size / align;
    //transaction* tx = (transaction*) malloc(sizeof(transaction)); // careful, things could be in positions other than you think. + nb_items * sizeof(int));
	transaction* tx = (transaction*) malloc(sizeof(transaction));
    if (unlikely(!tx)) {
        return invalid_tx;
    }
    tx->readonly = is_ro;
    
    if(is_ro){  
        int * timest = NULL;
        timest = (int *) malloc(nb_items * sizeof(int));
        if (unlikely(!timest)) {
        	return invalid_tx;
   		}
   		
   		int * rset = NULL;
   		rset = (int *) malloc(nb_items * sizeof(int));
   		for(size_t i = 0; i< nb_items; i++){
   		    rset[i] = 0;
   		}
   		tx->readset     = rset;
        tx->timestamps  = timest;
        // consider storing target addresses
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
        
        //void* source_item = tm_start(shared);
        for(size_t i = 0; i< nb_items; i++){
            wset[i] = 0;
            rset[i] = 0;
            //source_item = (char*) source_item + align;
            //printf("<tm_begin> init items %d \n", timest[i]);
        }
        tx->writeset    = wset;
        tx->readset     = rset;
        tx->timestamps  = timest;
        tx->local_copy  = init_v; // not initialized, could set all entries to null
        //printf("<tm_begin> init correctly \n");
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
    size_t size = tm_size(shared);
    size_t align = tm_align(shared);
    size_t nb_items = size / align;
    //printf("Ending trasaction %s\n", txn->readonly?"RO":"WR");
    if(txn->readonly){
        bool validated = tm_validateRO(shared, tx, nb_items);    
        if(!validated){
            tm_abort(shared, tx);
            return false; 
        }
        else{
           //printf("<tm_end>RO successful\n");
            free(txn->readset);
            free(txn->timestamps);
            free(txn);
            return true;
        }
    }
    else{
        bool validated = tm_validate(shared, tx, nb_items);
        if(!validated){
            tm_abort(shared, tx);
            return false; 
        }
        void* start = tm_start(shared);
        //printf("<tm_END> WR trying \n");
        for(size_t i = 0; i < nb_items; i++){ // copy piece by piece in shared memory + update the timestamp atomically
            if(txn->writeset[i] == 1){  // for what is in the readset has already been read each previous RW step
                void * next_shared_address = (align * i) + (char *) start;
                //printf("PREaccount %lu = %d\n", i, next_shared_address);
               //printf("AFT account %lu = %d\n", i, txn->local_copy[i*align]);
                atomic_fetch_add_explicit(&share->t_var[i].ts, 1, memory_order_acquire);
                memcpy(next_shared_address, &txn->local_copy[i*align], align);
            }
        }
        for(size_t i = 0; i < nb_items; i++){ // copy piece by piece in shared memory + update the timestamp atomically
            if(txn->writeset[i] == 1){
                int res = lock_release(&share->t_var[i].mutex);
                setFalse(&share->t_var[i].lock_flag);
            }
        }
        
		free(txn->local_copy);
        free(txn->writeset);
        free(txn->readset);
        free(txn->timestamps);
        free(txn);
        //printf("<tm_END> \tWR success\n");
        return true;
    }
}


// Whether the whole transaction can continue
bool tm_read(shared_t shared as(unused), tx_t tx as(unused), void const* source as(unused), size_t size as(unused), void* target as(unused)) {
	struct region * share = (struct region *) shared;
	transaction * txn = (transaction *) tx;
    size_t region_size = tm_size(share);
    size_t align = tm_align(shared);
    size_t nb_items = region_size / align;
    if(size % align != 0){ // if assumption holds align should be == size for reads
        tm_abort(share, txn);
        return false;
    }

    size_t mem_index = get_index(share, source);
    //printf("try R [%lu] while lock == %d copy = %d\n", mem_index, share->t_var[mem_index].ts, txn->local_copy[mem_index*align]);
    if(mem_index > nb_items){ 
        //printf("index %lu > %lu region_size\n", mem_index, nb_items);
        return false;
    }
    if(txn->readonly){
        setTSg2l(&txn->timestamps[mem_index], share->t_var[mem_index].ts);
        if(txn->readset[mem_index] == 0){
            setOne(&txn->readset[mem_index]); // PROBABLY PROBLEM HERE, while READING I could get past timestamp and read new value instead!
        }
        if((!(share->t_var[mem_index].lock_flag))){
            if((int) share->t_var[mem_index].ts == txn->timestamps[mem_index]){
                memcpy(target, source, size);
                return true;
            }
            else{
                tm_abort(shared,tx);
                return false;
            }
        }
        else{
            tm_abort(shared,tx);
            return false;
        }
    }
    if(size == align){
        if(txn->writeset[mem_index] ==1){
            memcpy(target, &txn->local_copy[mem_index*align], align);
            setOne(&txn->readset[mem_index]);
            return true;
        }
        else if(txn->readset[mem_index] == 1 && share->t_var[mem_index].lock_flag == false){
            int validated = tm_validate(shared, tx, nb_items);
            if(validated){
                memcpy(target, source, align);
                setTSg2l(&txn->timestamps[mem_index], share->t_var[mem_index].ts);
                return true;
            }
            tm_abort(shared, tx);
            return false;
        }
        else{// new value to read
            int validated = tm_validate(shared, tx, nb_items);
            if(validated){
                memcpy(target, source, align);
                setOne(&txn->readset[mem_index]);
                setTSg2l(&txn->timestamps[mem_index], share->t_var[mem_index].ts);
                //txn->timestamps[mem_index] = atomic_load_explicit(&share->t_var[mem_index].ts, memory_order_acquire);
                return true;
            }else{
                 tm_abort(shared, tx);
                 return false;
             }
        }
    }
    
    
    
   printf("SIZE >1 WORD & %s\n", txn->readonly?"Read-Only":"Read-Write");
    // this is going to be used if size > align and !txn->readonly
    size_t items = get_nb_items(size, align);
   //printf("multi word read START\n");
    for(size_t i = mem_index; i < (items + mem_index); i++){  // reading from where the process asks
        if(txn->writeset[i]==0){ // item not in tx write_set
            if(share->t_var[i].lock_flag == true){
               tm_abort(shared, tx);
               return false;
            }
            break;
        }
        if(i == (items + mem_index - 1)){ // finished loop without encountering a non-wset element-> hence can read immediately -> wrong! I must read my own local_copy with the updates!
            //memcpy(target, source, size); // if you have previously modified them then there's no need to "re-read" AKA copy them on themselves
           //printf("multi word read OK\n");
            memcpy(target, &txn->local_copy[mem_index*align], size);
            //try 
            return true;
        }
    }
	bool res = tm_validate(shared, tx, nb_items);
    if(!res){ // HERE
        tm_abort(shared, tx); 
        return false;
    }
    for(size_t i = mem_index; i < (items + mem_index); i++){
        if(txn->readset[i]==0){ // item not in tx read_set yet // here correct finding the highest timestamp instead and updating it for every piece of memory?
            setOne(&txn->readset[i]);
            txn->readset[i] = 1;
            setTSg2l(&txn->timestamps[mem_index], share->t_var[mem_index].ts);
            //txn->timestamps[i] = atomic_load_explicit(&share->t_var[i].ts, memory_order_acquire);
        }
    }
    memcpy(target, source, size); // WRONG IF TX HAS MADE CHANGES AND HENCE YOU SHOULD READ FROM LOCAL UPDATES
    //memcpy(&txn->local_copy[mem_index*align], source, size); // try both HERE * ALIGN or NOT
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
	
	if(txn->readonly){
	   //printf("weird\n");
	    tm_abort(shared, tx);
	    return false;
	}
	size_t region_size = tm_size(share);
    size_t align = tm_align(share); // what about size == 0?
    if(size % align != 0 || size == 0){
        tm_abort(shared, tx);
        return false;
    }
    ////printf("tm_write \t source %p \n", target);
    size_t mem_index = get_index(share, target); // you know where the target will go
    ////printf("tm_write \t index \t %lu\n", mem_index);
    size_t items = get_nb_items(size, align);
    size_t all_items = region_size / align;
    
    if((mem_index + items) > all_items){
        tm_abort(shared, tx);
        return false;
    }
    ////printf("tm_write \t nb_items \t %lu\n", nb_items);
    if(items == 1){
        if((txn->writeset[mem_index])==1){
            memcpy(&txn->local_copy[mem_index*align], source, align);
            return true;
        }
        else{
            if(lock_acquire(&share->t_var[mem_index].mutex)){
                setTrue(&share->t_var[mem_index].lock_flag);
                int sharedts = atomic_load_explicit(&share->t_var[mem_index].ts, memory_order_acquire);
                setTS(&txn->timestamps[mem_index], sharedts);
                setOne(&txn->writeset[mem_index]);
                memcpy(&txn->local_copy[mem_index*align], source, align);
                return true;
            }else{
                tm_abort(shared, tx);
                return false;
            }
        }
    }
    else{
       //printf("multi word write proceding\n");
        void* next_src_item = source;
        for(size_t i = mem_index; i < (items + mem_index); i++){ // HERE copy from "source"[i] to local_copy[i]
                //printf("<tm_write> \ttimes*align \t \n", txn->writeset[i*align]);
                //printf("<tm_write>  \tnormal \t\n", txn->writeset[i*align]);
                if((txn->writeset[i])==0){ // item not in tx write_set // set lock_flag = true; must be atomic
                    if(lock_acquire(&share->t_var[i].mutex)){ // try to add it, plus get the timestamp in an atomic way
                        setTrue(&share->t_var[i].lock_flag);
                        txn->timestamps[i] = atomic_load_explicit(&share->t_var[i].ts, memory_order_acquire);
                        // ICI
                        setOne(&txn->writeset[i]);
                        memcpy(&txn->local_copy[i*align], next_src_item, align);
                        //printf("tm_write next_src \t %p\n", (int) &txn->local_copy[i*align]);
                    }
                    else{
                        tm_abort(shared, tx); // HERE
                        return false;
                    }
                }
                else if((txn->writeset[i])==1){
                    //printf("<tm_write> already in writeset \n");
                    memcpy(&txn->local_copy[i*align], next_src_item, align); // if TX already holds the lock then just write the small fragment in its local_copy
                    //printf("<tm_write> in writeset memcopy successful \n");
                } // IF WRITESET[i] for whatever reason != 0 or 1 data will be messed up
                else{
                    tm_abort(shared, tx); // HERE
                    return false;
                }
            //update next_item
            next_src_item = align + (char *) next_src_item; // update position "+1"
        }
        // perhaps need to update the ts for all to the highest found during the iterations
        //memcpy(&txn->local_copy[mem_index*align], source, size); // need to be sure that local_copy in memory has distance from one item to the other == align
        return true;
    }
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
