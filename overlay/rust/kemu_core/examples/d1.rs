fn main(){ for w in [0xdac00365u32,0x5ac0004f,0xdac001fe,0x5ac0061c,0x1b047c1bu32]{
  println!("{:#010x} -> {:?}", w, kemu_core::decode::decode(w)); } }
