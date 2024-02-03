<?php

$config = new PhpCsFixer\Config();
$config
     ->setFinder(
         PhpCsFixer\Finder::create()
             ->exclude(['vendor', 'tmp'])
             ->in(__DIR__)
             ->name('*.php')
             ->ignoreDotFiles(true)
             ->ignoreVCS(true)
     )
     ->setRiskyAllowed(false)
     ->setRules([
         'declare_equal_normalize'                => true,
         'heredoc_to_nowdoc'                      => true,
         'multiline_whitespace_before_semicolons' => true,
         'spaces_inside_parentheses'              => false,
         'no_unused_imports'                      => true,
         'no_useless_return'                      => true,
         'no_whitespace_before_comma_in_array'    => true,
         'no_whitespace_in_blank_line'            => true,
         'not_operator_with_successor_space'      => false,
         'ordered_imports'                        => true,
         'phpdoc_add_missing_param_annotation'    => true,
         'phpdoc_order'                           => true,
         'return_type_declaration'                => true,
         'unary_operator_spaces'                  => true,
         'trailing_comma_in_multiline'            => true,
         '@PSR2'                                  => true,
         'array_indentation'                      => true,
         'array_syntax'                           => ['syntax' => 'short'],
         'binary_operator_spaces'                 => [
             'default'   => null,
             'operators' => [
                 '=>' => 'align_single_space_minimal',
             ],
         ],
         'concat_space' => [
             'spacing' => 'one',
         ],
     ]);
return $config;
