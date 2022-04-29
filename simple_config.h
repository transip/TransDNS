#ifndef __SIMPLE_CONFIG_H
#define __SIMPLE_CONFIG_H

/**
 * Simple Config Module, a module for reading simple config files with only
 * support for key=value pairs. To make this module more useful, multiple
 * key=value pairs with the same key are supported, making it possible to use
 * lists (e.g. ip=10.1.1.1, ip=10.1.1.2, ip=10.1.1.3, etc).
 * 
 * Features:
 *  - reads key=value pair config files
 *  - supports comments # anywhere in the script
 *  - multiple pairs with the same key are supported 
 *  = strips whitespace around keys and values
 *  - basic quote support, "key"= "value  ", to preserve whitespace
 *  - escaping of \n, \r, \t, \\, \" in quoted strings
 * 
 * Note that this is a very naive and suboptimal implementation using
 * simple vectors and uses malloc() for allocating dynamic buffers.
 *
 * Performance considerations:
 *  + reading a config file is done using fgetc(), without memory
 *    mapping or block allocation.
 *  + every value or count lookup is an O(n) operation, no hash tables
 *    or caching is used.
 *
 * Known problems: 
 *  + it's impossible to use the comment (#) and seperator (=) characters
 *      in a quoted string correctly. Just don't do it :-)
 */

#include <stdlib.h>

typedef char* zstring_t;
typedef const char* czstring_t;

typedef struct
{
    zstring_t key;
    zstring_t value;

} config_entry_t;

typedef struct
{
    size_t num_entries_allocated;
    size_t num_entries;

    config_entry_t* entries;

} config_file_t;

/**
 * Opens a config_file from a filename.
 *
 * @param zstring_t filename the name of the file to open as config file
 * @return config_file_t* a config_file handle if successfull, NULL otherwise
 */
config_file_t* config_file_open(const czstring_t filename);

/**
 * Closes a previously opened config file
 *
 * @param config_file_t* config_file the config_file to close
 * @return int 0 on failure, any other value on success
 */
int config_file_close(config_file_t* config_file);

/**
 * Gets a string config entry
 *
 * Note that since multiple keys of the same name are supported,
 * the index parameter is used to differentiate between all the keys with
 * the same name.
 *
 * @param config_file_t* config_file the config file to read the entry from
 * @param zstring_t key the key to get the value for
 * @param zstring_t default_value the value that needs to be returned if
 *                                  the requested key or index does not exist
 * @param size_t index the index of the keyed value to get; 0 is always the
 *                              first instance of the key, 1 the second, etc
 * @return czstring_t if the key and index is available, its value will
 *                              be returned, the default_value otherwise
 */
czstring_t config_file_get_string(config_file_t* config_file,
    czstring_t key,
    czstring_t default_value,
    size_t index);

/**
 * Gets a int config entry
 *
 * Note that since multiple keys of the same name are supported,
 * the index parameter is used to differentiate between all the keys with
 * the same name.
 *
 * @param config_file_t* config_file the config file to read the entry from
 * @param czstring_t key the key to get the value for
 * @param int default_value the value that needs to be returned if
 *                                  the requested key or index does not exist
 * @param size_t index the index of the keyed value to get; 0 is always the
 *                              first instance of the key, 1 the second, etc
 * @return int if the key and index is available, its value will be returned
 *                              if its convertible to an integer, otherwise,
 *                              the value will be 0.
 *                              if the key or index are not defined, the
 *                              default_value will be returned.
 */
int config_file_get_int(config_file_t* config_file,
    czstring_t key,
    int default_value,
    size_t index);

/**
 * Gets a boolean config entry
 *
 * Note that since multiple keys of the same name are supported,
 * the index parameter is used to differentiate between all the keys with
 * the same name.
 *
 * AVE_BOOL_TRUE_STRINGS is used to define all the strings that evaluate
 * to true.
 *
 * @param config_file_t* config_file the config file to read the entry from
 * @param czstring_t key the key to get the value for
 * @param int default_value the value that needs to be returned if
 *                                  the requested key or index does not exist
 * @param size_t index the index of the keyed value to get; 0 is always the
 *                              first instance of the key, 1 the second, etc
 * @return int if the key and index is available, true will be returned
 *                  if the value is a expression that is regarded as true,
 *                  false otherwise.
 *                  if the key or index is not defined, the default_value
 *                  will be returned.
 */
int config_file_get_bool(config_file_t* config_file,
    czstring_t key,
    int default_value,
    size_t index);

/**
 * Gets the number of key=value pairs for a certain key.
 * 
 * @param config_file_t* config_file* the config file to read from
 * @param czstring_t key the key to get the count for
 * @return size_t the number of key=value pairs in this config_file
 *                that have the requested key. If no pairs with the requested
 *                key are present, 0 is returned.
 */
size_t config_file_key_count(config_file_t* config_file,
    czstring_t key);

#endif //__SIMPLE_CONFIG_H
