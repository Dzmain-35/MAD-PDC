rule Axis_Control
{
    meta:
        author = "Dylan"
        description = "Detects abused access control remote agent"

    strings:
        $string1 = "axiscontrol.ltd"
        $string2 = "AxisControlAgent.dll"
	      $string3 = "C:\\ProgramData\\AxisControl"

    condition:
        any of them
}
