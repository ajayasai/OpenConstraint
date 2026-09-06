proc make_clock {name port period} {
    set waveform [list 0 [expr {$period / 2.0}]]
    create_clock -name $name -period $period -waveform $waveform [get_ports $port]
}
