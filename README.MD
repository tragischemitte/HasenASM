# Clientlauncher Class File Converter

---

## Overview

This project is a specialized toolkit designed for interoperability with Clientlauncher's custom Java class file format. It provides the necessary utilities to both encrypt and decrypt class files, enabling analysis, modification, and research.

## Features

* **Class Decryption:** Converts Clientlauncher's encrypted classes back into the standard Java class file format, allowing them to be opened in decompilers and analysis tools like Recaf.
* **Class Encryption:** Encrypts standard Java class files into Clientlauncher's proprietary format, allowing developers to run custom or modified code within its environment.

## Usage

`java -jar converter.jar <e/d> *input file* *output file*`

For example when decrypting all classes inside a jar file: 

`java -jar converter.jar d input.jar output.jar`

Or when encrypting a singular class to run on Clientlauncher JDK:

`java -jar converter.jar e input.class output.class`

## Background and Motivation

Clientlauncher utilizes a modified OpenJDK runtime that implements a non-standard class file loading mechanism. This project was born out of a reverse-engineering effort to understand and replicate this mechanism.

The two modifications addressed by this tool are:

* **Constant Pool Encryption:** A simple, keyless XOR cipher is applied to the UTF-8 strings within the class constant pool. This tool correctly applies and reverses this transformation.
* **Custom Opcode Mapping:** Integer arithmetic instructions have been remapped to different opcodes. This converter correctly translates between the standard and custom opcode sets during the conversion process.

This tool was created for educational purposes to demonstrate the process of analyzing and working with custom Java runtimes.

## Credits

* **ObjectWeb ASM:** This project is a fork of and builds directly upon the powerful ASM bytecode manipulation framework.
* **Clientlauncher:** The subject of this reverse-engineering study.
