# source2binary_dataset_construction
 
This is the repository for the paper "One to One or One to many? What function inline brings to binary similarity analysis" submitted to ICSE 2022.

Folder "construction" shows some scripts to extract the binaries. "construction\Dockerfile_source2binary" is a Dockerfile for compiling coreutils v8.29 using clang-10 and O0-O3 options. Run "docker build -t image_owner/image_name -f Dockerfile_source2binary ." to build an image containing the source and binary of coreutils.

The following tables show the dataset I mentioned in the paper.

 |package   | version |
 |  ----  | ----  |
 |binutils  | 2.33.1, 2.34, 2.35, 2.36, 2.36.1 | 
 |coreutils | 2.28, 8.29, 8.30, 8.31, 8.32 |
 |findutils | 4.4.1, 4.4.2, 4.6.0, 4.7.0, 4.8.0 |
 |gzip      | 1.10, 1.6, 1.7, 1.8, 1.9 |

 |setting   | options |
 |  ----  | ----  |
 |Compilers     |gcc-4.9.4, gcc-5.5.0, gcc-6.4.0, gcc-6.4.0, gcc-6.4.0, clang-4.0, clang-5.0, clang-6.0, clang-7.0 |
 |Optimizations | O0, O1, O2, O3, Os      |                                                                                                                      
 |Architectures | x86\_32, x86\_64        |     


The dataset containing 20 versions of 4 projects compiled in 9 compilers with 5 options can be download by link:
https://drive.google.com/drive/folders/1p8zi7nOOHbFc81UD2TGEYc9E4IUeUyaE?usp=sharing                                                                                                              

In this link, dataset_binaries.tgz contains all the binaries, dataset_sources.tgz contains all the source projects, and ground_truth.tgz contains the line level and function level labels for binary2source matching.

Folder "ground_truth_building" contains the code to automatically label the above dataset. Details can refer to our paper after review.
