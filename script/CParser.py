import os
from tree_sitter import Language, Parser
import tree_sitter_c as tsc
import tree_sitter_cpp as tsp

class CParser:
    def __init__(self):
        """Initialize the C/C++ parser with tree-sitter."""
        # Create a parser
        self.parser = Parser()
        
        self.C_LANGUAGE = Language(tsc.language())
        self.CPP_LANGUAGE = Language(tsp.language())
    
    def parse_file(self, file_path, file_type='c'):
        """
        Parse a C/C++ file and return its syntax tree.
        
        Args:
            file_path: Path to the source file
            file_type: 'c' or 'cpp'
            
        Returns:
            Tuple of (source_code, tree)
        """
        # Set appropriate language
        if file_type.lower() in ('c', '.c', 'h', '.h'):
            self.parser.language = self.C_LANGUAGE
        else:  # cpp, cc, cxx, hpp, etc.
            self.parser.language = self.CPP_LANGUAGE
        
        # Read and parse the file
        with open(file_path, 'rb') as f:
            source_code = f.read()
        
        tree = self.parser.parse(source_code)
        return source_code, tree
    
    def find_context_at_position(self, source_code, tree, line, column):
        """Find the context (function/class) at the specified position."""
        # Find the specific node at the position
        point = (line, column)
        node = tree.root_node
        
        # Navigate to the most specific node containing the point
        while True:
            found_child = False
            for child in node.children:
                if (child.start_point[0] <= point[0] <= child.end_point[0] and
                    ((child.start_point[0] < point[0]) or 
                     (child.start_point[0] == point[0] and child.start_point[1] <= point[1])) and
                    ((child.end_point[0] > point[0]) or 
                     (child.end_point[0] == point[0] and child.end_point[1] >= point[1]))):
                    node = child
                    found_child = True
                    break
            if not found_child:
                break
                
        # Find containing function or class/struct
        return self._get_containing_context(node, source_code)
    
    def _get_containing_context(self, node, source_code):
        """Get containing function or class/struct for a node."""
        current = node
        context = {
            'function': None,
            'class_or_struct': None
        }
        
        # Walk up the tree to find containing contexts
        while current:
            # Check for function definition
            if current.type == 'function_definition' and not context['function']:
                context['function'] = self._extract_function_info(current, source_code)
            
            # Check for class/struct definition
            if current.type in ('struct_specifier', 'class_specifier') and not context['class_or_struct']:
                context['class_or_struct'] = self._extract_class_info(current, source_code)
                
            current = current.parent
            
        return context
    
    def _extract_function_info(self, node, source_code):
        """Extract function signature, name, code and line information from a function_definition node."""
        # Get function body to determine where signature ends
        body = node.child_by_field_name('body')
        if not body:
            return None
            
        # Extract the signature (everything before the body)
        signature = source_code[node.start_byte:body.start_byte].decode('utf8').strip()
        
        # Extract the full code for the function
        function_code = source_code[node.start_byte:node.end_byte].decode('utf8')
        
        # Get line information
        start_line = node.start_point[0] + 1  # Convert to 1-based indexing
        end_line = node.end_point[0] + 1
        
        # Find function name
        declarator = node.child_by_field_name('declarator')
        name = "unknown"
        if declarator:
            # Find identifier in declarator using recursive traversal
            def find_identifier(node):
                if node.type == 'identifier':
                    return source_code[node.start_byte:node.end_byte].decode('utf8')
                for child in node.children:
                    found = find_identifier(child)
                    if found:
                        return found
                return None
                
            found_name = find_identifier(declarator)
            if found_name:
                name = found_name
        
        return {
            'name': name,
            'signature': signature,
            'code': function_code,
            'start_point': start_line,
            'end_point': end_line
        }
    
    def _extract_class_info(self, node, source_code):
        """Extract class/struct information from a class_specifier or struct_specifier node."""
        type_name = 'class' if node.type == 'class_specifier' else 'struct'
        
        # Find name node
        name = "anonymous"
        for child in node.children:
            if child.type == 'type_identifier':
                name = source_code[child.start_byte:child.end_byte].decode('utf8')
                break
        
        return {
            'type': type_name,
            'name': name
        }

    def iterate_code(self, file_path, file_type='c'):
        """
        Iterate through the code in a file and yield information about each context.
        
        Args:
            file_path: Path to the file
            file_type: 'c' or 'cpp'
            
        Yields:
            Dict with context information for each significant node
        """
        source_code, tree = self.parse_file(file_path, file_type)
        
        # Query to find functions and struct/class definitions
        # Choose the appropriate query based on language determination
        # C++ language query
        query_str = """
        (declaration) @func_decl
        (type_definition) @func_decl
        (enum_specifier) @func_decl
        (function_definition) @function
        (struct_specifier) @struct
        (class_specifier) @class
        (namespace_definition) @namespace
        (preproc_function_def) @macro
        """
        query_cpp = self.CPP_LANGUAGE.query(query_str)
        # C language query - no class_specifier or namespace_definition in C
        query_str = """
        (declaration) @func_decl
        (type_definition) @func_decl
        (enum_specifier) @func_decl
        (function_definition) @function
        (struct_specifier) @struct
        (preproc_function_def) @macro
        """
        query_c= self.C_LANGUAGE.query(query_str)

        captures = query_c.captures(tree.root_node)
        if len(captures) == 0:
            captures = query_cpp.captures(tree.root_node)
        for _, node_list in captures.items():
            for node in node_list:
                if node.type == 'function_definition':
                    info = self._extract_function_info(node, source_code)
                    if not info:
                        # Sometimes tree-sitter parse wrong functions, Skip them
                        continue
                    yield {
                        'type': 'function',
                        'name': info['name'], 
                        'signature': info['signature'],
                        'code': source_code[node.start_byte:node.end_byte].decode('utf8'),
                        'start_point': node.start_point,
                        'end_point': node.end_point
                    }
                elif node.type in ('struct_specifier', 'class_specifier'):
                    info = self._extract_class_info(node, source_code) # "class" or "struct"
                    if not info:
                        # Sometimes tree-sitter parse wrong classes, Skip them
                        continue
                    yield {
                        'type': info['type'],
                        'name': info['name'],
                        'code': source_code[node.start_byte:node.end_byte].decode('utf8'),
                        'start_point': node.start_point,
                        'end_point': node.end_point
                    }


    def function_signature(self, file_path, line_number, column_number, file_type):
        """
        Get the function signature at a specific line and column in a file.
        
        Args:
            file_path: Path to the file
            line_number: Line number (1-based)
            column_number: Column number (0-based)
            
        Returns:
            Function signature or None if not found
        """
        source_code, tree = self.parse_file(file_path, file_type)
        context = self.find_context_at_position(source_code, tree, int(line_number) - 1, column_number)
        return context['function']['signature'] if context['function'] else None


    def get_code_context(self, file_path, line_number, column_number, file_type):
        """
        Get the function/class context at a specific line and column in a file.
        
        Args:
            file_path: Path to the file
            line_number: Line number (1-based)
            column_number: Column number (0-based)
            
        Returns:
            Function signature or None if not found
        """
        source_code, tree = self.parse_file(file_path, file_type)
        context = self.find_context_at_position(source_code, tree, int(line_number) - 1, column_number)
        return context if context['function'] else None


    def find_function_calls(self, file_path, file_type='c'):
        source_code, tree = self.parse_file(file_path, file_type)
        root = tree.root_node
        calls = []

        def traverse(node):
            if node.type == 'call_expression':
                # Function being called
                function_node = node.child_by_field_name('function')
                if function_node:
                    func_name = source_code[function_node.start_byte:function_node.end_byte].decode('utf8')
                else:
                    func_name = "unknown"

                calls.append({
                    'name': func_name,
                    'start_point': node.start_point,
                    'end_point': node.end_point,
                    'code': source_code[node.start_byte:node.end_byte].decode('utf8')
                })

            for child in node.children:
                traverse(child)

        traverse(root)
        return calls


def example_usage():
    """Example demonstrating the usage of the CParser class."""
    # Initialize the parser
    parser = CParser()
    
    # Example 1: Parse a C file and get its syntax tree
    file_path = "example.c"  # Replace with your C/C++ file path
    source_code, tree = parser.parse_file(file_path, file_type='c')
    print(f"Parsed {file_path}, tree has {len(tree.root_node.children)} top-level nodes")
    
    # Example 2: Find context at a specific position (line 10, column 5)
    context = parser.find_context_at_position(source_code, tree, 10, 5)
    if context['function']:
        print(f"Position is in function: {context['function']['name']}")
    if context['class_or_struct']:
        print(f"Position is in {context['class_or_struct']['type']}: {context['class_or_struct']['name']}")
    
    # Example 3: Iterate through all functions and classes/structs
    print("\nAll functions and classes/structs in the file:")
    for item in parser.iterate_code(file_path, file_type='c'):
        if item['type'] == 'function':
            print(f"Function: {item['name']}")
            print(f"Signature: {item['signature']}")
        else:
            print(f"{item['type'].capitalize()}: {item['name']}")
        print(f"Location: Lines {item['start_point'][0]+1}-{item['end_point'][0]+1}")
        print("---")

# Example to run the parser
if __name__ == "__main__":
    example_usage()