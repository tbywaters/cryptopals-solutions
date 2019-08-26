""" A collection of functions which are used for manipulating string when
solving the cryptopals challenges"""


def kequalsv_to_dict(kequalsv_str):
    """Splits a string into chucnks using & as separators. Builds a dictionary
    from each chunk using = as a separtor for keys and values.
    eg:
        'foo=bar&baz=qux&zap=zazzle' -> {'foo':'bar, 'baz':qux, 'zap':'zazzle}
    """
    result = {}
    splits = kequalsv_str.split('&')
    
    for split in splits:
        entry_pair = split.split('=')
        
        # If a split does not contain the character =, add the whole split as 
        # a key with an empty string value
        if len(entry_pair) == 1:
            entry_pair.append('')

        # If a split contains more than one =, only use the first as a split.
        # Keep excess = in the value
        if len(entry_pair) > 2:
            entry_pair[1] = '='.join(entry_pair[1:])

        result[entry_pair[0]] = entry_pair[1]
    
    return result

def remove_meta_chars(input_string, meta_chars):

    for char in meta_chars:
        input_string = input_string.replace(char, '')
    
    return input_string

