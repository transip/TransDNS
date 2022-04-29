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

#include "simple_config.h"

#include <assert.h> // assert()
#include <ctype.h> // tolower()
#include <memory.h> // malloc(), free(), realloc()
#include <stdio.h> // fopen(), fgetc(), fclose()

// for convenience
#define AVE_ASSERT(x) assert(x)

// used for parsing the config entries
#define CONFIG_FILE_SEPERATOR_CHAR '='
#define CONFIG_FILE_COMMENT_CHAR '#'
#define CONFIG_FILE_QUOTE_CHAR '"'
#define CONFIG_FILE_ESCAPE_CHAR '\\'

// used in config_file_get_bool,
// only these values will evaluate to "true"
static czstring_t AVE_BOOL_TRUE_STRINGS[] = {
    "true",
    "t",
    "yes",
    "oui",
    "ja",
    "1",
    "ok"
};

// helper macros
#define AVE_IS_WHITESPACE(c) (' ' == (c) || '\t' == (c) || '\n' == (c) || '\r' == (c))

#define AVE_COUNTOF(x) sizeof((x)) / sizeof((x)[0])

/**
 * Helper function that trims a string, with respect to  quotes being used:
 * If a string is wrapped inside quotes, the whitespace inside the quotes
 * will be preserved. In additional, a couple of escape characters
 * can be used in the quoted string also, such as \n, \t and \r.
 *
 * @param zstring_t str the string to trim
 * @return zstring_t a trimmed copy of the string is returned, or
 *                      NULL when memory could not be allocated.
 *                   The caller gets ownership of the returned string and
 *                   should free it using the free() function.
 *
 * @internal
 */
static zstring_t config_file_trim_copy(zstring_t str)
{
    AVE_ASSERT(str != NULL);
    if (NULL == str) {
        return NULL;
    }

    // our simple state machine
    int in_quote_mode = 0;
    int prev_is_escape = 0;
    char* last_nonwhitespace_char = NULL;

    // we allocate a result buffer which is guaranteed to be large enough:
    // it's impossible for the result to be larger that the input, because
    // we only remove characters. In fact, the buffer will probably be somewhat
    // larger than needed.
    size_t len = strlen(str);
    size_t index = 0;
    zstring_t trimmed = (zstring_t)malloc(len + 1);
    if (NULL == trimmed) {
        return NULL;
    }

    while (*str != '\0') {
        char c = *str;

        // only skip whitespaces when not in quote mode
        if (!AVE_IS_WHITESPACE(c) || in_quote_mode) {
            if (in_quote_mode) {
                // when in quote mode, we always preserve whitespace
                // until we hit the closing quote.
                last_nonwhitespace_char = str;

                if (prev_is_escape) {
                    // if the previous character was the escape character,
                    // interpret the current character as a special "character"
                    // or just copy it over to support slashes and quotes to
                    // be escaped. As a side effect, "\x" will simply output "x".
                    prev_is_escape = 0;
                    if ('n' == c)
                        trimmed[index++] = '\n';
                    else if ('t' == c)
                        trimmed[index++] = '\t';
                    else if ('r' == c)
                        trimmed[index++] = '\r';
                    else
                        trimmed[index++] = c;

                } else if (CONFIG_FILE_ESCAPE_CHAR == c) {
                    // if you want a slash, escape it like "\\"
                    prev_is_escape = 1;
                } else if (CONFIG_FILE_QUOTE_CHAR == c) {
                    // end quote, done
                    break;
                } else {
                    // not an escape(d) character, simply copy it over
                    trimmed[index++] = c;
                }

            } else {
                // if we haven't started yet, check if we need to go into
                // quote_mode where we have to preserve spaces. the upfront
                // whitespace is skipped.
                if (last_nonwhitespace_char == NULL && CONFIG_FILE_QUOTE_CHAR == c) {
                    in_quote_mode = 1;
                } else if (last_nonwhitespace_char != NULL) {
                    // we initial skip all whitespace, but we now found
                    // out it is embedded (e.g. "a    b", so copy
                    // all skipped whitespace over.
                    while (last_nonwhitespace_char != str) {
                        last_nonwhitespace_char++;
                        trimmed[index++] = *last_nonwhitespace_char;
                    }
                } else {
                    // first non-whitespace character
                    trimmed[index++] = c;
                    last_nonwhitespace_char = str;
                }
            }
        }

        str++;
    }

    trimmed[index] = '\0';
    return trimmed;
}

/**
 * Adds a key=value pair entry to a config_file
 *
 * @note can possibly reallocate memory using realloc
 * 
 * @param config_file_t* config_file the config file to add the entry to
 * @param czstring_t key the key of the entry to add
 * @param czstring_t value the value of the entry to add
 * @return int 0 on failure, any other value on success
 *
 * @internal
 */
static int config_file_add_entry(config_file_t* config_file,
    zstring_t key,
    zstring_t value)
{
    config_entry_t* new_ptr;

    AVE_ASSERT(config_file != NULL);
    AVE_ASSERT(key != NULL);
    AVE_ASSERT(value != NULL);

    if (NULL == config_file || NULL == key || NULL == value) {
        return 0;
    }

    if (config_file->num_entries >= config_file->num_entries_allocated) {
        config_file->num_entries_allocated *= 2;
        new_ptr = (config_entry_t*)malloc(config_file->num_entries_allocated * sizeof(config_entry_t));
        memmove(new_ptr, config_file->entries, sizeof(config_entry_t) * config_file->num_entries);
        free(config_file->entries);
        config_file->entries = new_ptr;
        /*
        config_file->entries = (config_entry_t*)realloc(config_file->entries,
                                       config_file->num_entries_allocated * sizeof(config_entry_t));
        */

        if (NULL == config_file->entries) {
            return 0;
        }
    }

    key = config_file_trim_copy(key);
    if (NULL == key) {
        return 0;
    }

    value = config_file_trim_copy(value);
    if (NULL == value) {
        free(key);
        return 0;
    }

    config_file->entries[config_file->num_entries].key = key;
    config_file->entries[config_file->num_entries].value = value;
    config_file->num_entries++;

    return 1;
}

/**
 * Internal function to parse a config file into a config_file_t structure.
 * This function basically tokenizes the input file one character at a time
 * and uses a very small state machine (implemented by 2 boolean variables
 * to be able to do this). 
 * The function will fail on memory allocation errors
 *
 * @internal
 *
 */
static int config_file_parse(config_file_t* config_file, FILE* file)
{
    // our state machine: seen seperator is true when we have tokenized the key,
    // ignore_chars is true when we have seen a comment indicator,
    // error is set when a memory allocation error occured.
    int seen_seperator = 0;
    int ignore_chars = 0;
    int error = 0;

    // we use 2 dynamically allocated buffers for the key and value
    // parts of a line. The buffers are resized on demand using realloc.
    size_t len_key = 64;
    size_t len_value = 128;

    size_t index_key = 0;
    size_t index_value = 0;

    zstring_t key = (zstring_t)malloc(len_key);
    zstring_t value = (zstring_t)malloc(len_value);

    int c = 0;
    do {
        c = fgetc(file);
        if ('\n' == c || EOF == c) {
            // we are only interested in the data if this is a
            // valid key=value line
            if (seen_seperator) {
                // these bufers are always large enough to append the
                // closing nil-terminator, since they are resized on demand.
                key[index_key] = '\0';
                value[index_value] = '\0';

                if (!config_file_add_entry(config_file, key, value)) {
                    error = 1;
                    break;
                }
            }

            // start with a new line, reset the state machine
            seen_seperator = 0;
            ignore_chars = 0;

            index_key = 0;
            index_value = 0;
        } else if (!ignore_chars) {
            if (CONFIG_FILE_COMMENT_CHAR == c) {
                // we've spotted a comment seperator, just ignore
                // everything till the end of the line
                ignore_chars = 1;
            } else if (CONFIG_FILE_SEPERATOR_CHAR == c && !seen_seperator) {
                // if we already have seen the seperator, we just
                // assume this seperator is part of the value
                // e.g. key=bla=x, bla=x will be the value
                seen_seperator = 1;
            } else {
                // a normal character, either part of the key or the value.
                // whitespace will be trimmed from the key and value
                // when adding them to the config_file structure.
                if (!seen_seperator) {
                    key[index_key++] = c;

                    // ensure enough buffer size, even for the nil terminator
                    if (index_key >= len_key - 1) {
                        len_key *= 2;
                        key = (zstring_t)realloc(key, len_key);
                        if (NULL == key) {
                            error = 1;
                            break;
                        }
                    }
                } else {
                    value[index_value++] = c;

                    // ensure enough buffer size, even for the nil terminator
                    if (index_value >= len_value - 1) {
                        len_value *= 2;
                        value = (zstring_t)realloc(value, len_value);
                        if (NULL == value) {
                            error = 1;
                            break;
                        }
                    }
                }
            }
        }
    } while (c != EOF);

    free(key);
    free(value);

    return !error;
}

/**
 * Opens a config_file from a filename.
 *
 * @param czstring_t filename the name of the file to open as config file
 * @return config_file_t* a config_file handle if successfull, NULL otherwise
 */
config_file_t* config_file_open(const czstring_t filename)
{
    FILE* file = fopen(filename, "r");
    if (NULL == file) {
        return NULL;
    }

    config_file_t* config_file = (config_file_t*)malloc(sizeof(config_file_t));
    if (config_file != NULL) {
        config_file->num_entries = 0;
        config_file->num_entries_allocated = 16;
        config_file->entries = (config_entry_t*)malloc(sizeof(config_entry_t)
            * config_file->num_entries_allocated);

        if (config_file->entries == NULL || !config_file_parse(config_file, file)) {
            config_file_close(config_file);
            config_file = NULL;
        }
    }

    fclose(file);

    return config_file;
}

/**
 * Closes a previously opened config file
 *
 * @param config_file_t* config_file the config_file to close
 * @return int 0 on failure, any other value on success
 */
int config_file_close(config_file_t* config_file)
{
    AVE_ASSERT(config_file != NULL);
    if (NULL == config_file) {
        return 0;
    }

    for (size_t i = 0; i < config_file->num_entries; ++i) {
        config_entry_t* entry = &config_file->entries[i];
        free(entry->key);
        free(entry->value);
    }

    free(config_file->entries);
    free(config_file);

    return 1;
}

/**
 * Checks if two strings are equal, case-insensitive.
 *
 * @note this function is not local aware, both strings
 *       are simply compared lowercased.
 *
 * @param czstring_t a the first string to compare against
 * @param czstring_t b the second string to compare against
 * @return 0 if the two strings are not case-insensitive equal,
 *         any other value if they are.
 *
 * @internal
 */
static int config_file_str_equals_nocase(czstring_t a, czstring_t b)
{
    const char* ptrA = a;
    const char* ptrB = b;

    while (*ptrA != '\0' && *ptrB != '\0' && tolower(*ptrA) == tolower(*ptrB)) {
        ptrA++;
        ptrB++;
    }

    return *ptrA == *ptrB;
}

/**
 * Finds a config entry by key and index.
 *
 * @param config_file_t* config_file the config file to search in
 * @param czstring_t key the key to get the entry for
 * @param size_t index the index of the key=value pairs with the same key
 *                      to get (0-based).
 *
 * @internal
 */
static config_entry_t* config_file_find_entry(config_file_t* config_file,
    czstring_t key,
    size_t index)
{
    AVE_ASSERT(config_file != NULL);
    AVE_ASSERT(key != NULL);
    if (NULL == config_file || NULL == key) {
        return NULL;
    }

    size_t count = 0;

    for (size_t i = 0; i < config_file->num_entries; ++i) {
        config_entry_t* entry = &config_file->entries[i];
        if (config_file_str_equals_nocase(entry->key, key)) {
            if (count == index) {
                return entry;
            }

            count++;
        }
    }

    return NULL;
}

/**
 * Gets the number of key=value pairs for a certain key.
 * 
 * @param config_file_t* config_file* the config file to read from
 * @param zstring_t key the key to get the count for
 * @return size_t the number of key=value pairs in this config_file
 *                that have the requested key. If no pairs with the requested
 *                key are present, 0 is returned.
 */
size_t config_file_key_count(config_file_t* config_file,
    czstring_t key)
{
    AVE_ASSERT(config_file != NULL);
    AVE_ASSERT(key != NULL);
    if (NULL == config_file || NULL == key) {
        return 0;
    }

    size_t count = 0;

    for (size_t i = 0; i < config_file->num_entries; ++i) {
        config_entry_t* entry = &config_file->entries[i];
        if (config_file_str_equals_nocase(entry->key, key)) {
            count++;
        }
    }

    return count;
}

/**
 * Gets a string config entry
 *
 * Note that since multiple keys of the same name are supported,
 * the index parameter is used to differentiate between all the keys with
 * the same name.
 *
 * @param config_file_t* config_file the config file to read the entry from
 * @param czstring_t key the key to get the value for
 * @param czstring_t default_value the value that needs to be returned if
 *                                  the requested key or index does not exist
 * @param size_t index the index of the keyed value to get; 0 is always the
 *                              first instance of the key, 1 the second, etc
 * @return czstring_t if the key and index is available, its value will
 *                              be returned, the default_value otherwise
 */
czstring_t config_file_get_string(config_file_t* config_file,
    czstring_t key,
    czstring_t default_value,
    size_t index)
{
    AVE_ASSERT(config_file != NULL);
    AVE_ASSERT(key != NULL);

    czstring_t value = default_value;
    if (config_file != NULL && key != NULL) {
        config_entry_t* entry = config_file_find_entry(config_file, key, index);
        if (entry != NULL) {
            value = entry->value;
        }
    }

    return value;
}

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
    size_t index)
{
    AVE_ASSERT(config_file != NULL);
    AVE_ASSERT(key != NULL);

    int value = default_value;
    if (config_file != NULL && key != NULL) {
        czstring_t string_value = config_file_get_string(config_file,
            key,
            NULL,
            index);
        if (string_value != NULL) {
            value = atoi(string_value);
        }
    }

    return value;
}

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
    size_t index)
{
    AVE_ASSERT(config_file != NULL);
    AVE_ASSERT(key != NULL);

    int value = default_value;
    if (config_file != NULL && key != NULL) {
        czstring_t string_value = config_file_get_string(config_file,
            key,
            NULL,
            index);
        if (string_value != NULL) {
            // by default, we interpret this value as false,
            // and we only regard it as true if its equal to one
            // of the predefined "true" strings.
            value = 0;
            for (size_t i = 0; i < AVE_COUNTOF(AVE_BOOL_TRUE_STRINGS); ++i) {
                if (config_file_str_equals_nocase(string_value,
                        AVE_BOOL_TRUE_STRINGS[i])) {
                    value = 1;
                    break;
                }
            }
        }
    }

    return value;
}
