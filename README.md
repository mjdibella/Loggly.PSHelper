# Loggly.PSHelper
A PowerShell module with helpful cmdlets for accessing the Loggly API

To install, create a subdirectory under the $env:PSModulePath directory named Loggly.PSHelper and copy the Loggly.PsHelper.psm1 file into that directory. Then create a shortcut to open a Loggly Powershell window with the command line:

powershell.exe -noExit -Command "& {Import-module Loggly.PSHelper.psm1}"
