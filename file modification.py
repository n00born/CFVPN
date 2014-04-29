_author__ = 'nicklewi'

#Function to open a file(filename), search it for text(searchtext), and replace each found text with (replacetext)

def findandreplace(filename, searchtext, replacetext):

    #Open file, split into a list
    file = open(filename, "r+")
    strfile = file.read().splitlines();

    #Replace text as needed then join into a string for export
    strfile = [str.replace(searchtext, replacetext) for str in strfile]
    outfile = '\n'.join(strfile)

    #Navigate to beggining of file, and write and close file, then return
    file.seek(0, 0);
    file.write(outfile)
    file.close()
    return True

#!!!End findandreplace function

"""
Example being run of the above function, replacing all
filename = "test.txt"
searchtext = "<LOCAL PRIVATE IP>"
replacetext = "52.1.1.1"
findandreplace(filename, searchtext, replacetext)

findandreplace(filename, '<CONN A PUBLIC IP>', '27.0.0.1')
findandreplace(filename, "<CONN B PUBLIC IP>", '27.0.0.2')
findandreplace(filename, "<CONN A LOCAL LINK>", '169.0.0.1')
findandreplace(filename, "<CONN B LOCAL LINK>", '169.1.0.1')
findandreplace(filename, "<CONN A REMOTE LINK>", '169.0.0.2')
findandreplace(filename, "<CONN B REMOTE LINK>", '169.1.0.2')
findandreplace(filename, "<LOCAL SUBNET>", '10.0.0.0/24')
findandreplace(filename, "<REMOTE SUBNET>", '10.1.0.0/24')
"""