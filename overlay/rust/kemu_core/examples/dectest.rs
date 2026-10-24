fn main(){
  for w in [0x9e660003u32, 0x9e670043, 0x1e604000] {
    println!("{:#x} -> {:?}", w, kemu_core::decode::decode(w));
  }
}
