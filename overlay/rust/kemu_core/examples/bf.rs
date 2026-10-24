use kemu_core::state::CpuState;
use kemu_core::env::{Env, Fault, Access};
struct E;
impl Env for E {
    fn fetch(&mut self,_:u64)->Result<u32,Fault>{Err(Fault{addr:0,access:Access::Exec,align:false})}
    fn read_u8(&mut self,_:u64)->Result<u8,Fault>{Ok(0)} fn read_u16(&mut self,_:u64)->Result<u16,Fault>{Ok(0)}
    fn read_u32(&mut self,_:u64)->Result<u32,Fault>{Ok(0)} fn read_u64(&mut self,_:u64)->Result<u64,Fault>{Ok(0)}
    fn write_u8(&mut self,_:u64,_:u8)->Result<(),Fault>{Ok(())} fn write_u16(&mut self,_:u64,_:u16)->Result<(),Fault>{Ok(())}
    fn write_u32(&mut self,_:u64,_:u32)->Result<(),Fault>{Ok(())} fn write_u64(&mut self,_:u64,_:u64)->Result<(),Fault>{Ok(())}
    fn cmpxchg(&mut self,_:u64,_:u32,_:[u64;2],_:[u64;2])->Result<[u64;2],Fault>{Ok([0,0])}
    fn cntvct(&mut self)->u64{0} fn cntfrq(&mut self)->u64{0} fn random(&mut self)->Option<u64>{Some(0)}
}
// expose a single-step via decode+a tiny runner using the public run with a fetch stub
fn exec1(word:u32, setup:impl Fn(&mut CpuState))->CpuState{
    // We can't easily call private step; emulate via a 1-insn program through run would need fetch.
    // Instead use a fetch env that returns `word` once then svc.
    struct F{w:u32,n:u32}
    impl Env for F{
        fn fetch(&mut self,_:u64)->Result<u32,Fault>{ self.n+=1; Ok(if self.n==1 {self.w} else {0xd4000001}) }
        fn read_u8(&mut self,_:u64)->Result<u8,Fault>{Ok(0)} fn read_u16(&mut self,_:u64)->Result<u16,Fault>{Ok(0)}
        fn read_u32(&mut self,_:u64)->Result<u32,Fault>{Ok(0)} fn read_u64(&mut self,_:u64)->Result<u64,Fault>{Ok(0)}
        fn write_u8(&mut self,_:u64,_:u8)->Result<(),Fault>{Ok(())} fn write_u16(&mut self,_:u64,_:u16)->Result<(),Fault>{Ok(())}
        fn write_u32(&mut self,_:u64,_:u32)->Result<(),Fault>{Ok(())} fn write_u64(&mut self,_:u64,_:u64)->Result<(),Fault>{Ok(())}
        fn cmpxchg(&mut self,_:u64,_:u32,_:[u64;2],_:[u64;2])->Result<[u64;2],Fault>{Ok([0,0])}
        fn cntvct(&mut self)->u64{0} fn cntfrq(&mut self)->u64{0} fn random(&mut self)->Option<u64>{Some(0)}
    }
    let mut cpu=CpuState::new(); setup(&mut cpu);
    let mut f=F{w:word,n:0};
    let _=kemu_core::interp::run(&mut cpu,&mut f,2);
    cpu
}
fn main(){
    let _=E;
    let c=exec1(0xd35a5aba,|c|{c.x[21]=0xffff_ffff_ffff_ffff;});
    println!("UBFM x26,x21,#26,#22 x21=all1 -> x26={:#x}", c.x[26]);
    let c=exec1(0x93591184,|c|{c.x[12]=0x1f;}); // x12[4:0]=0x1f -> sext=-1 <<39
    println!("SBFM x4,x12,#25,#4 x12=0x1f -> x4={:#x}", c.x[4]);
    let c=exec1(0xd370a1c7,|c|{c.x[14]=0x1ff_ffff_ffff;}); // low 41 bits set
    println!("UBFM x7,x14,#48,#40 -> x7={:#x} (expect <<16 of x14[40:0])", c.x[7]);
    // adds w27, wsp, #0xa76
    let c=exec1(0x3129dbfb,|c|{c.sp=0x1000;});
    println!("ADDS w27,wsp,#0xa76 sp=0x1000 -> w27={:#x} (expect 0x1a76)", c.x[27]);
}
