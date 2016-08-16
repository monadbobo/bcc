set(EXAMPLE_FILES README.txt simulation.py vlan_learning.c broadcast.c)
set(EXAMPLE_PROGRAMS vlan_learning.py broadcast.py)
install(FILES ${EXAMPLE_FILES} DESTINATION share/bcc/examples/networking/vlan_learning)
install(PROGRAMS ${EXAMPLE_PROGRAMS} DESTINATION share/bcc/examples/networking/vlan_learning)
